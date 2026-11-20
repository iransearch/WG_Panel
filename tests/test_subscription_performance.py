import os
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from sqlalchemy import event, inspect

from models import InterfaceConfig, Peer, Subscription, SubscriptionPeer, db


class SubscriptionPerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.lock = Path(temporary.name) / 'expiry.lock'
        with patch.dict(os.environ, {
            'DATABASE_URL': os.environ.get('WG_PANEL_TEST_DATABASE_URL', 'sqlite:///:memory:'),
            'FERNET_KEY': Fernet.generate_key().decode(),
            'API_KEY': 'subscription-test',
        }), patch('threading.Thread.start'):
            import app
        cls.panel = app
        with cls.panel.app.app_context():
            cls.addClassCleanup(db.engine.dispose)

    def setUp(self):
        self.context = self.panel.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        if inspect(db.engine).get_table_names():
            self.fail('Subscription tests require an empty test database.')
        db.create_all()
        self.addCleanup(db.drop_all)
        self.addCleanup(db.session.remove)
        self.client = self.panel.app.test_client()
        self.headers = {'X-API-KEY': 'subscription-test'}

    def add_clients(self, count):
        iface = InterfaceConfig(
            name='test-awg', path='/tmp/test-awg.conf', address='10.1.0.1/24',
            listen_port=51820, private_key='fixture',
        )
        for i in range(count):
            peer = Peer(
                name=f'Peer {i}', iface=iface, public_key=f'public-{i}',
                private_key='fixture', address=f'10.1.0.{i + 2}/32', status='online',
            )
            sub = Subscription(name=f'Client {i}', token=f'token-{i}')
            db.session.add(SubscriptionPeer(subscription=sub, peer=peer))
        db.session.commit()
        db.session.remove()

    def test_list_is_batched_and_legacy_shape_is_preserved(self):
        self.add_clients(20)
        calls = []
        engine = db.engine

        def count_queries(conn, cursor, statement, *args):
            calls.append(statement)

        event.listen(engine, 'before_cursor_execute', count_queries)
        self.addCleanup(event.remove, engine, 'before_cursor_execute', count_queries)
        with patch.object(self.panel, '_expire') as expire, patch.object(
            self.panel, '_wg_runtime_snapshot', return_value=({}, {}),
        ) as snapshot, patch.object(self.panel, '_wg_transfer') as per_peer:
            response = self.client.get('/api/subscriptions', headers=self.headers)
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(set(payload), {'subscriptions'})
            self.assertEqual(len(payload['subscriptions']), 20)
            self.assertLessEqual(len(calls), 4)
            snapshot.assert_called_once()
            expire.assert_not_called()
            per_peer.assert_not_called()

    def test_page_search_and_focus_keep_global_summary(self):
        self.add_clients(12)
        with patch.object(self.panel, '_wg_runtime_snapshot', return_value=({}, {})):
            response = self.client.get(
                '/api/subscriptions?page=1&per_page=5&focus=1&scope=local&status=ready',
                headers=self.headers,
            )
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(payload['pagination'], {'page': 3, 'per_page': 5, 'pages': 3, 'total': 12})
            self.assertIn(1, [row['id'] for row in payload['subscriptions']])
            response = self.client.get('/api/subscriptions?page=1&q=10.1.0.13', headers=self.headers)
            payload = response.get_json()
            self.assertEqual(payload['pagination']['total'], 1)
            self.assertEqual(payload['summary']['total'], 12)
            self.assertEqual(payload['subscriptions'][0]['name'], 'Client 11')

    def test_one_sweep_updates_counters_first_use_and_shared_quota(self):
        self.add_clients(2)
        subs = Subscription.query.order_by(Subscription.id).all()
        first_peer = subs[0].links[0].peer
        subs[0].start_on_first_use = True
        subs[0].time_limit_days = 1
        subs[1].data_limit_value = 1
        subs[1].data_limit_unit = 'Mi'
        db.session.commit()

        now = self.panel.now_ts()
        keys = [('test-awg', 'public-0'), ('test-awg', 'public-1')]
        with patch.object(self.panel, '_wg_runtime_snapshot', return_value=(
            {keys[0]: (100, 200), keys[1]: (2**20, 0)}, {keys[0]: now},
        )) as snapshot, patch.object(
            self.panel, '_block_subscription_runtime', return_value=False,
        ) as block:
            self.panel._expire()
        self.assertEqual(first_peer.used_bytes_total, 300)
        self.assertEqual(self.panel.to_ts(subs[0].first_used_at), now)
        self.assertEqual(self.panel.to_ts(subs[0].expires_at), now + 86400)
        block.assert_called_once_with(subs[1], 'subscription_data_exhausted')
        snapshot.assert_called_once()

    def test_expired_subscription_is_blocked_without_live_counters(self):
        self.add_clients(1)
        sub = Subscription.query.one()
        sub.created_at = self.panel.from_ts(self.panel.now_ts() - 2 * 86400)
        sub.time_limit_days = 1
        peer = sub.links[0].peer
        peer.bytes_offset = 400
        peer.used_bytes_total = 800
        db.session.commit()

        with patch.object(self.panel, '_wg_runtime_snapshot', return_value=({}, {})), patch.object(
            self.panel, '_block_subscription_runtime', return_value=False,
        ) as block:
            self.panel._expire()
        block.assert_called_once_with(sub, 'subscription_expired')
        self.assertEqual((peer.bytes_offset, peer.used_bytes_total), (400, 800))

    def test_irspeedy_allocates_beyond_200000_occupied_hosts(self):
        subnet = ip_network('10.64.0.0/14')
        first_ip = int(subnet.network_address) + 1
        occupied = {ip_address(i) for i in range(first_ip, first_ip + 200_000)}
        iface = InterfaceConfig(
            name='test-awg', path='/tmp/test-awg.conf', address='10.66.66.1/14',
            listen_port=51820, private_key='fixture',
        )
        db.session.add(iface)
        db.session.commit()

        saved_hosts = self.panel._db_peer_hosts

        def occupied_hosts(*args, **kwargs):
            return occupied | saved_hosts(*args, **kwargs)

        with patch.object(self.panel, '_db_peer_hosts', side_effect=occupied_hosts), patch.object(
            self.panel, '_wg_allowed_ips', return_value=set(),
        ), patch.object(self.panel, 'install_local_peer'), patch.object(
            self.panel.subprocess, 'check_output', side_effect=[b'private-test', b'public-test'],
        ):
            response = self.client.post(
                '/api/irspeedy/subscriptions',
                headers={**self.headers, 'Idempotency-Key': 'f' * 64},
                json={'name': 'Large pool', 'targets': [{'scope': 'local', 'iface': iface.name}]},
            )
            self.assertEqual(response.status_code, 201, response.get_json())
            allocated = ip_address(first_ip + 200_000)
            self.assertEqual(Peer.query.one().address, f'{allocated}/14')
            self.assertEqual(self.panel._available_ips(iface, limit=2), [
                f'{ip_address(int(allocated) + 1)}/14', f'{ip_address(int(allocated) + 2)}/14',
            ])

    def test_allocator_observes_live_and_saved_reservations(self):
        conf = self.lock.with_name('alloc-awg.conf')
        conf.write_text('[Interface]\nAddress = 10.66.66.1/29\n[Peer]\nAllowedIPs = 10.66.66.4/32\n')
        iface = InterfaceConfig(
            name='alloc-awg', path=str(conf), address='10.66.66.1/29',
            listen_port=51820, private_key='fixture',
        )
        db.session.add(Peer(
            name='Reserved DB', iface=iface, public_key='db-public',
            private_key='fixture', address='10.66.66.5/29',
        ))
        db.session.commit()
        runtime = b'other-peer\t10.66.66.2/32 10.66.66.3/32\n'
        with patch.object(self.panel.subprocess, 'check_output', return_value=runtime):
            self.assertEqual(self.panel.allocate_peer_address(iface), '10.66.66.6/29')
            self.assertEqual(self.panel._available_ips(iface), ['10.66.66.6/29'])
            with self.assertRaises(self.panel.AddressConflict):
                self.panel.allocate_peer_address(iface, requested='10.66.66.3')
            with self.assertRaises(self.panel.AddressPoolExhausted):
                self.panel.allocate_peer_address(iface, extra_reserved=['10.66.66.6'])

    def test_large_ipv6_pool_and_point_to_point_bounds(self):
        with patch.object(self.panel, '_reserved_hosts', side_effect=lambda _, address, **kwargs: {address.ip}):
            for cidr, expected in [
                ('fd00::1/64', ['fd00::2/64', 'fd00::3/64']),
                ('fd00::/127', ['fd00::1/127']),
                ('10.0.0.0/31', ['10.0.0.1/31']),
                ('10.0.0.1/32', []),
            ]:
                with self.subTest(cidr=cidr), patch.object(
                    self.panel, 'interface_ip_interface', return_value=ip_interface(cidr),
                ):
                    self.assertEqual(self.panel._available_ips(object(), limit=2), expected)

    def test_https_html_keeps_upgrade_policy_without_obsolete_directive(self):
        response = self.client.get('/login', base_url='https://localhost')
        self.assertIn('upgrade-insecure-requests', response.headers['Content-Security-Policy'])
        self.assertNotIn('block-all-mixed-content', response.headers['Content-Security-Policy'])

    def test_config_download_checks_live_quota_before_next_sweep(self):
        self.add_clients(1)
        sub = Subscription.query.one()
        sub.data_limit_value = 1
        sub.data_limit_unit = 'Mi'
        db.session.commit()
        with patch.object(self.panel, '_wg_runtime_snapshot', return_value=(
            {('test-awg', 'public-0'): (2**20, 0)}, {},
        )):
            response = self.client.get('/s/token-0/config')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()['reason'], 'data_exhausted')
        self.assertEqual(sub.links[0].peer.used_bytes_total, 0)

    def test_expiry_lock_prevents_two_sweeps_in_same_interval(self):
        self.lock.unlink(missing_ok=True)
        with patch.object(self.panel, '_EXPIRY_LOCK_PATH', self.lock), patch.object(
            self.panel, '_expire',
        ) as sweep:
            self.panel._run_expiry_once()
            self.panel._run_expiry_once()
        sweep.assert_called_once()


if __name__ == '__main__':
    unittest.main()
