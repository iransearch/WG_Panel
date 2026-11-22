import os
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from gzip import decompress
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
from subprocess import TimeoutExpired
from threading import Barrier, get_ident
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from requests import ConnectionError
from sqlalchemy import event, inspect

from models import AdminAccount, InterfaceConfig, Node, OperationEvent, Peer, Subscription, SubscriptionPeer, db


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

    def test_dashboard_counts_recent_users_once_and_reports_missing_sources(self):
        self.add_clients(9)
        path = '/api/dashboard/peer-activity'
        with self.panel.app.app_context():
            self.assertEqual(self.client.get(path).status_code, 302)
        db.session.add(AdminAccount(username='dashboard-test', password_hash='unused'))
        node = Node(name='Edge', base_url='https://edge.example.test', api_key='test-key')
        peers = Peer.query.order_by(Peer.id).all()
        peers[1].subscription_links[0].subscription_id = peers[0].subscription_links[0].subscription_id
        peers[2].status = 'blocked'
        peers[3].subscription_links[0].subscription.enabled = False
        peers[4].iface = InterfaceConfig(
            name='edge-wg', node=node, path='/tmp/edge-wg.conf', address='10.2.0.1/24',
            listen_port=51820, private_key='fixture',
        )
        db.session.commit()
        with self.client.session_transaction() as session:
            session['_user_id'] = '1'
            session['_fresh'] = True

        now = 1000
        # The stale peer has traffic counters, and the blocked peers still have recent handshakes.
        local_dump = ''.join(
            f'test-awg\tpublic-{i}\t(none)\t(none)\t10.1.0.{i + 2}/32\t{timestamp}\t1024\t2048\t0\n'
            for i, timestamp in enumerate([990, 820, 998, 999, 0, 819, 600, 500, 400])
        ).encode()
        remote = {'peers': [{
            'iface': 'edge-wg', 'public_key': 'public-4', 'latest_handshake': 2000,
            'latest_handshake_age': 4, 'rx_bytes': 512, 'tx_bytes': 256,
        }]}
        with patch.object(self.panel, 'now_ts', return_value=now), patch.object(
            self.panel.subprocess, 'check_output', return_value=local_dump,
        ) as awg, patch.object(self.panel._node_client, 'get', return_value=remote) as remote_get:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
            data = response.get_json()
            self.assertEqual(data['online_users'], 2)
            self.assertEqual(data['counts'], dict(online=3, inactive=4, blocked=2, unknown=0))
            self.assertEqual([peer['name'] for peer in data['recent']], ['Peer 4', 'Peer 0', 'Peer 1', 'Peer 5', 'Peer 6'])
            self.assertEqual(data['recent'][0]['node'], 'Edge')
            self.assertNotIn('public_key', data['recent'][0])
            awg.assert_called_once()
            self.assertEqual(awg.call_args.args[0], ['awg', 'show', 'all', 'dump'])
            remote_get.assert_called_once_with(node.base_url, '/api/peers?counters_only=1', node.api_key, timeout=3)

            remote_get.return_value = {'peers': [], 'runtime_available': False}
            partial = self.client.get(path).get_json()
            self.assertEqual(partial['online_users'], 1)
            self.assertEqual(partial['counts']['unknown'], 1)
            awg.side_effect = TimeoutExpired('awg', 2)
            self.assertIsNone(self.client.get(path).get_json()['online_users'])

            awg.side_effect = None
            awg.return_value = b''
            remote_get.return_value = {'peers': [], 'runtime_available': True}
            data = self.client.get(path).get_json()
            self.assertEqual(data['online_users'], 0)
            self.assertEqual(data['counts']['unknown'], 0)

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
             400, 'invalid_node_target'),
        ]:
            with self.subTest(targets=targets), patch.object(self.panel, 'install_local_peer') as install:
                invalid = self.client.post(
                    '/api/irspeedy/subscriptions', headers={**self.headers, 'Idempotency-Key': 'b' * 64},
                    json={'name': 'Invalid interfaces', 'targets': targets},
                )
                self.assertEqual(invalid.status_code, status)
                self.assertEqual(invalid.get_json()['error'], error)
                install.assert_not_called()

    def test_irspeedy_provisions_a_node_and_all_interfaces_with_one_feed(self):
        self.add_irspeedy_interfaces()
        node = Node(name='Node A', base_url='https://node.example.test:8443', api_key='node')
        disabled = Node(name='Disabled', base_url='https://disabled.example.test', api_key='node', enabled=False)
        db.session.add_all([node, disabled])
        db.session.commit()
        node_id = node.id
        remote = [
            {'name': 'wg0', 'address': '10.64.0.1/14', 'listen_port': 52611},
            {'name': 'wg1', 'address': '10.68.0.1/14', 'listen_port': 52612},
        ]
        for row in remote:
            row['public_key'] = b64encode(bytes([72]) * 32).decode()

        def node_get(target, url, **kwargs):
            self.assertEqual(target.id, node_id)
            if url == '/api/interfaces?fast=1':
                return {'interfaces': remote}
            if url == '/api/interfaces':
                return {'interfaces': remote}
            if url == '/api/health':
                return {'public_ipv4': '198.51.100.23'}
            if url.endswith('/awg-parameters'):
                return {'parameters': {'Jc': '4'}}
            self.fail(f'Unexpected Agent request {url}')

        with (
            patch.object(self.panel, 'node_get', side_effect=node_get) as inventory,
            patch.object(self.panel, 'node_post', side_effect=[
                {'host_cidr': '10.64.0.2/32'},
                {'host_cidr': '10.64.0.3/32'},
                {'host_cidr': '10.68.0.2/32'},
            ]) as install_node,
            patch.object(self.panel, 'install_local_peer') as install_local,
            patch.object(self.panel, '_wg_allowed_ips', return_value=set()),
            patch.object(self.panel.subprocess, 'check_output',
                         side_effect=[b64encode(bytes([n]) * 32) for n in range(1, 11)]),
        ):
            capability = self.client.get(
                f'/api/irspeedy/capabilities?node_id={node_id}&iface=wg0',
                headers=self.headers,
            )
            self.assertEqual(capability.status_code, 200, capability.json)
            self.assertEqual(capability.json['server_cidr'], '10.64.0.1/14')
            self.assertIsNone(capability.json['iface_id'])
            capability = self.client.get('/api/irspeedy/capabilities?iface=all', headers=self.headers)
            self.assertEqual([t['scope'] for t in capability.json['targets']], ['local', 'local', 'node', 'node'])

            single = self.client.post(
                '/api/irspeedy/subscriptions',
                headers={**self.headers, 'Idempotency-Key': 'd' * 64},
                json={'name': 'Node client', 'node_id': node_id, 'iface': 'wg0'},
            )
            self.assertEqual(single.status_code, 201, single.json)
            self.assertEqual(len(single.json['subscription']['interface_ids']), 1)

            all_headers = {**self.headers, 'Idempotency-Key': 'e' * 64}
            inventory.reset_mock()
            result = self.client.post(
                '/api/irspeedy/subscriptions', headers=all_headers,
                json={'name': 'All interfaces', 'targets': 'all', 'include_internal_network': True},
            )
            self.assertEqual(result.status_code, 201, result.json)
            inventory.assert_called_once_with(node, '/api/interfaces?fast=1', timeout=10)
            self.assertEqual(install_local.call_count, 2)
            self.assertEqual([call.args[2]['iface'] for call in install_node.call_args_list],
                             ['wg0', 'wg0', 'wg1'])

            sub = db.session.get(Subscription, result.json['subscription']['id'])
            peers = [link.peer for link in sorted(sub.links, key=lambda link: link.sort_order)]
            self.assertEqual([peer.iface.name for peer in peers],
                             ['wg0', 'wg1', f'n{node_id}:wg0', f'n{node_id}:wg1'])
            self.assertEqual([peer.address for peer in peers],
                             ['10.60.0.2/29', '10.60.1.2/29', '10.64.0.3/14', '10.68.0.2/14'])
            self.assertTrue(peers[0].allowed_ips.endswith('10.60.0.0/29'))
            self.assertTrue(peers[2].allowed_ips.endswith('10.64.0.0/14'))

            replay = self.client.post(
                '/api/irspeedy/subscriptions', headers=all_headers, json={'targets': 'all'},
            )
            self.assertEqual(replay.status_code, 200, replay.json)
            self.assertEqual(replay.json, result.json)
            self.assertEqual(inventory.call_count, 1)

            feed = self.client.get(urlsplit(result.json['subscription']['feed_url']).path)
            self.assertEqual(feed.status_code, 200, feed.get_data(as_text=True))
            self.assertEqual([urlsplit(uri).netloc for uri in feed.get_data(as_text=True).splitlines()],
                             ['wg0.example.test:51820', 'wg1.example.test:51821',
                              '198.51.100.23:52611', '198.51.100.23:52612'])

    def test_irspeedy_all_fails_before_creating_peers_when_a_node_is_unreachable(self):
        self.add_irspeedy_interfaces()
        db.session.add(Node(name='Unreachable', base_url='https://unreachable.example.test', api_key='node'))
        db.session.commit()
        with (
            patch.object(self.panel, 'node_get', side_effect=ConnectionError),
            patch.object(self.panel, 'node_post') as install_node,
            patch.object(self.panel, 'install_local_peer') as install_local,
        ):
            response = self.client.post(
                '/api/irspeedy/subscriptions',
                headers={**self.headers, 'Idempotency-Key': '5' * 64},
                json={'targets': 'all'},
            )
            self.assertEqual(response.status_code, 502)
            self.assertEqual(response.json['error'], 'node_unreachable')
            install_local.assert_not_called()
            install_node.assert_not_called()
        self.assertEqual(Subscription.query.count(), 0)

    def test_irspeedy_all_rolls_back_node_peers_when_a_later_install_fails(self):
        node = Node(name='Rollback node', base_url='https://rollback.example.test', api_key='node')
        db.session.add(node)
        db.session.commit()
        with (
            patch.object(self.panel, 'node_get', return_value={'interfaces': [
                {'name': 'awg0', 'address': '10.64.0.1/14', 'listen_port': 52000},
                {'name': 'awg1', 'address': '10.68.0.1/14', 'listen_port': 52001},
            ]}),
            patch.object(self.panel, 'node_post', side_effect=[
                {'host_cidr': '10.64.0.2/32'}, ConnectionError('Agent disconnected'),
            ]),
            patch.object(self.panel, 'node_delete', return_value={
                'ok': True, 'config_removed': True, 'runtime_removed': True,
            }) as remove,
            patch.object(self.panel.subprocess, 'check_output', side_effect=[b'priv1', b'pub1', b'priv2', b'pub2']),
        ):
            response = self.client.post(
                '/api/irspeedy/subscriptions',
                headers={**self.headers, 'Idempotency-Key': '8' * 64},
                json={'targets': 'all'},
            )
            self.assertEqual(response.status_code, 502)
            self.assertTrue(response.json['cleanup_complete'])
            self.assertEqual([call.kwargs['payload']['public_key'] for call in remove.call_args_list],
                             ['pub2', 'pub1'])
        self.assertEqual(Subscription.query.count(), 0)
        self.assertEqual(Peer.query.count(), 0)
        self.assertEqual(InterfaceConfig.query.count(), 0)

    def test_irspeedy_concurrent_first_use_of_a_node_interface_shares_one_mirror(self):
        node = Node(name='Concurrent node', base_url='https://race.example.test', api_key='node')
        db.session.add(node)
        db.session.commit()
        node_id = node.id
        mirror_name = f'n{node_id}:race0'
        engine = db.engine
        db.session.remove()
        barrier = Barrier(2)
        threads_seen = set()

        def synchronize_first_lookup(conn, cursor, statement, params, context, executemany):
            thread_id = get_ident()
            if thread_id not in threads_seen and 'WHERE interface_config.name =' in statement and mirror_name in str(params):
                threads_seen.add(thread_id)
                barrier.wait(timeout=10)

        event.listen(engine, 'after_cursor_execute', synchronize_first_lookup)
        try:
            with (
                patch.object(self.panel, 'node_get', return_value={'interfaces': [
                    {'name': 'race0', 'address': '10.72.0.1/14', 'listen_port': 52000},
                ]}),
                patch.object(self.panel, 'node_post', side_effect=[
                    {'host_cidr': '10.72.0.2/32'}, {'host_cidr': '10.72.0.3/32'},
                ]),
                patch.object(self.panel.subprocess, 'check_output', side_effect=[b'priv1', b'pub1', b'priv2', b'pub2']),
            ):
                def create(token):
                    return self.panel.app.test_client().post(
                        '/api/irspeedy/subscriptions',
                        headers={**self.headers, 'Idempotency-Key': token * 64},
                        json={'node_id': node_id, 'iface': 'race0'},
                    )

                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(create, ('6', '7')))
        finally:
            event.remove(engine, 'after_cursor_execute', synchronize_first_lookup)

        self.assertEqual([result.status_code for result in results], [201, 201],
                         [result.json for result in results])
        self.assertEqual(InterfaceConfig.query.filter_by(name=mirror_name).count(), 1)
        self.assertEqual(Subscription.query.count(), 2)
        self.assertEqual({peer.address for peer in Peer.query.all()}, {'10.72.0.2/14', '10.72.0.3/14'})

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
