import os
from base64 import b64encode
from gzip import decompress
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from sqlalchemy import event, inspect

from models import AdminAccount, InterfaceConfig, OperationEvent, Peer, Subscription, SubscriptionPeer, db


class SubscriptionPerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database_url = os.environ.get('WG_PANEL_TEST_DATABASE_URL')
        if not database_url:
            raise unittest.SkipTest('Set WG_PANEL_TEST_DATABASE_URL to an empty PostgreSQL database.')
        temporary = TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.lock = Path(temporary.name) / 'expiry.lock'
        with patch.dict(os.environ, {
            'DATABASE_URL': database_url,
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

    def add_irspeedy_interfaces(self):
        interfaces = []
        for index, name in enumerate(('wg0', 'wg1')):
            conf = self.lock.with_name(f'{name}.conf')
            conf.write_text(f'[Interface]\nAddress = 10.60.{index}.1/29\nJc = 4\n')
            interfaces.append(InterfaceConfig(
                name=name, path=str(conf), address=f'10.60.{index}.1/24',
                listen_port=51820 + index, private_key='fixture',
                public_key=b64encode(bytes([40 + index]) * 32).decode(),
                endpoint_host=f'{name}.example.test', endpoint_port=51820 + index,
            ))
        db.session.add_all(interfaces)
        db.session.commit()
        return interfaces

    def test_irspeedy_provisions_two_peers_with_one_subscription_and_feed(self):
        wg0, wg1 = self.add_irspeedy_interfaces()
        headers = {**self.headers, 'Idempotency-Key': 'a' * 64}
        data = {
            'name': 'Dual interface', 'data_limit_value': 10,
            'targets': [{'scope': 'local', 'iface': 'wg1'}, {'scope': 'local', 'iface_id': wg0.id}],
        }
        keys = [b64encode(bytes([byte]) * 32) for byte in range(1, 5)]
        with (
            patch.object(self.panel.subprocess, 'check_output', side_effect=keys),
            patch.object(self.panel, '_wg_allowed_ips', return_value=set()),
            patch.object(self.panel, '_check_iface_up'),
            patch.object(self.panel, '_wg_enable') as enable,
            patch.object(self.panel, '_derive_wg_public_key', return_value=''),
        ):
            capability = self.client.get('/api/irspeedy/capabilities?iface=wg1', headers=headers)
            self.assertEqual(capability.get_json()['max_local_targets'], 2)
            response = self.client.post('/api/irspeedy/subscriptions', headers=headers, json=data)
            self.assertEqual(response.status_code, 201, response.get_json())
            subscription = response.get_json()['subscription']
            self.assertEqual(subscription['interface_ids'], [wg1.id, wg0.id])
            self.assertEqual(Subscription.query.count(), 1)
            links = SubscriptionPeer.query.order_by(SubscriptionPeer.sort_order).all()
            self.assertEqual([(link.owned, link.peer.name, link.peer.address) for link in links], [
                (True, 'Dual interface-1', '10.60.1.2/29'),
                (True, 'Dual interface-2', '10.60.0.2/29'),
            ])
            self.assertEqual(len({link.peer.public_key for link in links}), 2)
            self.assertTrue(all(link.peer.data_limit_value == 10 for link in links))
            for link in links:
                self.assertIn(link.peer.public_key, Path(link.peer.iface.path).read_text())

            feed = self.client.get(urlsplit(subscription['feed_url']).path)
            self.assertEqual(feed.status_code, 200)
            self.assertEqual([urlsplit(uri).netloc for uri in feed.get_data(as_text=True).splitlines()], [
                'wg1.example.test:51821', 'wg0.example.test:51820',
            ])
            replay = self.client.post('/api/irspeedy/subscriptions', headers=headers, json=data)
            self.assertEqual(replay.status_code, 200)
            self.assertEqual(replay.get_json()['subscription'], subscription)
            self.assertEqual(enable.call_count, 2)

        for targets, status, error in [
            ([{'scope': 'local', 'iface': 'wg0'}, {'scope': 'local', 'iface_id': wg0.id}],
             400, 'duplicate_local_interface'),
            ([{'scope': 'local', 'iface': 'wg0'}, {'scope': 'local', 'iface': 'missing'}],
             404, 'local_interface_not_found'),
            ([{'scope': 'local', 'iface': 'wg0'}, {'scope': 'node', 'iface': 'wg1'}],
             400, 'local_interface_required'),
        ]:
            with self.subTest(targets=targets), patch.object(self.panel, 'install_local_peer') as install:
                invalid = self.client.post(
                    '/api/irspeedy/subscriptions', headers={**self.headers, 'Idempotency-Key': 'b' * 64},
                    json={'name': 'Invalid interfaces', 'targets': targets},
                )
                self.assertEqual(invalid.status_code, status)
                self.assertEqual(invalid.get_json()['error'], error)
                install.assert_not_called()

    def test_irspeedy_removes_both_peers_when_second_install_fails(self):
        interfaces = self.add_irspeedy_interfaces()
        files = {Path(iface.path): Path(iface.path).read_text() for iface in interfaces}
        install = self.panel.install_local_peer

        def fail_after_writing_second_peer(peer):
            install(peer)
            if peer.iface.name == 'wg1':
                raise RuntimeError('Injected failure after writing the second peer')

        with (
            patch.object(self.panel.subprocess, 'check_output', side_effect=[b'priv-0', b'pub-0', b'priv-1', b'pub-1']),
            patch.object(self.panel, '_wg_allowed_ips', return_value=set()),
            patch.object(self.panel, '_check_iface_up'),
            patch.object(self.panel, '_iface_up', return_value=True),
            patch.object(self.panel, '_wg_peer_keys', return_value=set()),
            patch.object(self.panel, '_wg_enable'),
            patch.object(self.panel, '_wg_disable') as disable,
            patch.object(self.panel, 'install_local_peer', side_effect=fail_after_writing_second_peer),
        ):
            response = self.client.post(
                '/api/irspeedy/subscriptions', headers={**self.headers, 'Idempotency-Key': 'c' * 64},
                json={'name': 'Dual interface', 'targets': [
                    {'scope': 'local', 'iface': 'wg0'}, {'scope': 'local', 'iface': 'wg1'},
                ]},
            )
            self.assertEqual(response.status_code, 500)
            self.assertTrue(response.get_json()['cleanup_complete'])
            self.assertEqual([call.args[0].public_key for call in disable.call_args_list], ['pub-1', 'pub-0'])

        self.assertEqual({file: file.read_text() for file in files}, files)
        self.assertEqual(Subscription.query.count(), 0)
        self.assertEqual(SubscriptionPeer.query.count(), 0)
        self.assertEqual(Peer.query.count(), 0)

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

    def test_subscription_studio_markup_is_served_separately(self):
        db.session.add(AdminAccount(username='studio-test', password_hash='unused'))
        db.session.commit()
        with self.client.session_transaction() as session:
            session['_user_id'] = '1'
            session['_fresh'] = True
        headers = {'Accept-Encoding': 'gzip'}
        page = self.client.get('/subscriptions', headers=headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'data-content-url="/static/subscription-studio.html"', page.data)
        self.assertNotIn(b'id="studio-preview-frame"', page.data)
        self.assertNotIn('Content-Encoding', page.headers)

        with self.client.get('/static/subscription-studio.html', headers=headers) as studio:
            self.assertEqual(studio.status_code, 200)
            self.assertEqual(studio.headers['Content-Encoding'], 'gzip')
            self.assertIn(b'id="studio-preview-frame"', decompress(studio.data))

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

    def test_operations_history_is_persisted_in_postgresql(self):
        db.session.add(AdminAccount(username='operator', password_hash='fixture'))
        db.session.commit()
        with self.client.session_transaction() as session:
            session['_user_id'] = '1'
            session['_fresh'] = True
        with patch('panel_operations.collect', return_value=[]):
            response = self.client.post('/api/operations/scan', json={})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(OperationEvent.query.one().kind, 'scan')
        response = self.client.get('/api/operations/history')
        self.assertEqual(response.get_json()['events'][0]['payload']['checks'], [])
        self.assertEqual(self.client.post('/api/operations/scan', json={}).status_code, 429)

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
