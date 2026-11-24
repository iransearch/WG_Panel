import os
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from gzip import decompress
from io import BytesIO
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
from subprocess import TimeoutExpired
from threading import Barrier, get_ident
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit
from zipfile import ZipFile

from cryptography.fernet import Fernet
from requests import ConnectionError
from sqlalchemy import event, inspect, text

from models import AdminAccount, InterfaceConfig, Node, OperationEvent, Peer, PeerEvent, ShortLink, Subscription, SubscriptionPeer, db


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

    def test_page_can_load_before_peer_runtime(self):
        self.add_clients(3)
        local, remote, hidden = Peer.query.order_by(Peer.id).all()
        node = Node(name='Edge', base_url='https://edge.example.test', api_key='test-key')
        remote.iface = InterfaceConfig(
            name='edge-wg', node=node, path='/tmp/edge-wg.conf', address='10.2.0.1/24',
            listen_port=51820, private_key='fixture',
        )
        hidden.status = 'blocked'
        visible = {
            peer.subscription_links[0].subscription_id: peer.subscription_links[0].id
            for peer in (local, remote)
        }
        local_id, remote_id = visible.keys()
        db.session.commit()

        with patch.object(self.panel, '_wg_runtime_snapshot') as local_runtime, patch.object(
            self.panel, 'node_get',
            return_value={'peers': [{'public_key': 'public-1', 'latest_handshake': self.panel.now_ts()}]},
        ) as node_get:
            response = self.client.get(
                '/api/subscriptions?page=1&runtime=deferred&status=ready', headers=self.headers,
            )
            self.assertEqual(response.status_code, 200)
            payload = response.json
            self.assertTrue(payload['runtime_deferred'])
            self.assertEqual(payload['summary']['total'], 3)
            self.assertEqual({row['id'] for row in payload['subscriptions']}, set(visible))
            self.assertTrue(all(row['connection']['runtime_count'] == 0 for row in payload['subscriptions']))
            local_runtime.assert_not_called()
            node_get.assert_not_called()

            activity_path = f'/api/subscriptions/activity?ids={local_id},{remote_id}'
            self.assertEqual(self.client.get(activity_path).status_code, 401)
            with self.panel.app.app_context():
                local_runtime.side_effect = TimeoutExpired('awg', 2)
                activity = self.client.get(activity_path, headers=self.headers)
            self.assertEqual(activity.status_code, 200)
            self.assertEqual(activity.headers['Cache-Control'], 'private, no-store')
            rows = {row['id']: row for row in activity.json['subscriptions']}
            self.assertEqual(set(rows), set(visible))
            self.assertEqual(set(rows[remote_id]), {'id', 'link_ids', 'connection'})
            self.assertEqual(rows[remote_id]['link_ids'], [visible[remote_id]])
            self.assertTrue(rows[remote_id]['connection']['connected'])
            self.assertEqual(rows[local_id]['connection']['runtime_count'], 0)
            local_runtime.assert_called_once_with(['test-awg'])
            self.assertEqual(node_get.call_args.args[1], '/api/peers?counters_only=1')
            self.assertEqual(node_get.call_args.kwargs['timeout'], 4)

            with self.panel.app.app_context():
                node_get.return_value = {'peers': [], 'runtime_available': False}
                unavailable = self.client.get(
                    f'/api/subscriptions/activity?ids={remote_id}', headers=self.headers,
                )
            self.assertEqual(unavailable.json['subscriptions'][0]['connection']['runtime_count'], 0)
            self.assertEqual(self.client.get('/api/subscriptions/activity?ids=1,0', headers=self.headers).status_code, 400)

    def test_dashboard_subscription_summary_counts_policies_without_peer_runtime(self):
        path = '/api/dashboard/subscription-summary'
        with self.panel.app.app_context():
            self.assertEqual(self.client.get(path).status_code, 302)
        admin = AdminAccount(username='dashboard-policy-test', password_hash='unused')
        db.session.add(admin)
        db.session.commit()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(admin.id)
            session['_fresh'] = True

        now = 1700000000
        with patch.object(self.panel, 'now_ts', return_value=now):
            empty = self.client.get(path)
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.json, dict(total=0, active=0, blocked=0, expiring_soon=0))
        db.session.remove()

        self.add_clients(7)
        subs = Subscription.query.order_by(Subscription.id).all()
        for sub in subs:
            sub.created_at = self.panel.from_ts(now)
        subs[0].time_limit_days = 8
        subs[1].time_limit_days = 7
        subs[2].time_limit_days = 1
        subs[2].timer_started_at = self.panel.from_ts(now - 86400)
        subs[3].enabled = False
        subs[3].unlimited = True
        subs[4].unlimited = True
        subs[4].time_limit_days = 1
        subs[5].data_limit_value = 1
        subs[5].data_limit_unit = 'Mi'
        first_peer = subs[5].links[0].peer
        first_peer.used_bytes_total = 512 * 1024
        second_peer = Peer(
            name='Second inbound', iface=first_peer.iface, public_key='second-public',
            private_key='fixture', address='10.1.0.50/32', used_bytes_total=512 * 1024,
        )
        db.session.add(SubscriptionPeer(subscription=subs[5], peer=second_peer))
        subs[6].start_on_first_use = True
        subs[6].time_limit_days = 1
        db.session.add(Subscription(name='No inbounds', token='unassigned-policy'))
        db.session.commit()
        db.session.remove()

        with (
            patch.object(self.panel, 'now_ts', return_value=now),
            patch.object(self.panel, '_subscription_row') as details,
            patch.object(self.panel, '_wg_runtime_snapshot') as runtime,
            patch.object(self.panel, 'node_get') as node_get,
        ):
            response = self.client.get(path)
            details.assert_not_called()
            runtime.assert_not_called()
            node_get.assert_not_called()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
        self.assertEqual(response.json, dict(total=8, active=5, blocked=3, expiring_soon=1))

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

    def test_interface_dns_survives_config_reload_and_reaches_subscription(self):
        iface, _ = self.add_irspeedy_interfaces()
        iface_id = iface.id
        path = f'/api/iface/{iface_id}'
        conf = Path(iface.path)
        peer_block = '[Peer]\nPublicKey = existing-peer\nAllowedIPs = 10.60.0.2/32'
        conf.write_text(
            '[Interface]\nAddress = 10.60.0.1/29\nPrivateKey = fixture\n'
            'ListenPort = 51820\nDNS = 1.1.1.1\nJc = 4\n\n' + peer_block,
        )
        key = b64encode(b'a' * 32).decode()
        peer = Peer(
            name='DNS test', iface=iface, public_key=key, private_key=key,
            address='10.60.0.2/32', status='online',
        )
        subscription = Subscription(name='DNS test', token='interface-dns-test')
        db.session.add(SubscriptionPeer(subscription=subscription, peer=peer))
        db.session.commit()
        expected = '8.8.8.8, 8.8.4.4'

        with (
            patch.object(self.panel, '_iface_up', return_value=False),
            patch.object(self.panel, '_endpoint_fallback', return_value=''),
            patch.object(self.panel, '_derive_wg_public_key', return_value=''),
            patch.object(self.panel, '_wg_runtime_snapshot', return_value=({}, {})),
            patch.object(self.panel, '_panel_default_dns', return_value='1.0.0.1'),
        ):
            response = self.client.post(
                path, headers=self.headers, json={'dns': expected, 'listen_port': 51820},
            )
            self.assertEqual(response.status_code, 200, response.json)
            saved = conf.read_text()
            self.assertEqual(saved.count('DNS = '), 1)
            self.assertIn(f'DNS = {expected}\n', saved.partition('[Peer]')[0])
            self.assertTrue(saved.endswith(peer_block))

            self.panel._copy_local_iface_from_parsed(iface, self.panel.find_iface(str(conf)))
            db.session.commit()
            self.assertEqual(self.client.get(path, headers=self.headers).json['dns'], expected)
            feed = self.client.get('/s/interface-dns-test/links')
            self.assertEqual(feed.status_code, 200)
            self.assertIn('dns=8.8.8.8%2C%208.8.4.4', feed.get_data(as_text=True))

            invalid = self.client.post(path, headers=self.headers, json={'dns': '8.8.8.8\nMTU = 576'})
            self.assertEqual(invalid.status_code, 400)
            self.assertEqual(conf.read_text(), saved)

            with patch.object(db.session, 'commit', side_effect=RuntimeError('test commit failure')):
                failed = self.client.post(path, headers=self.headers, json={'dns': '9.9.9.9'})
            self.assertEqual(failed.status_code, 500)
            self.assertEqual(conf.read_text(), saved)
            self.assertEqual(self.client.get(path, headers=self.headers).json['dns'], expected)

            clear = self.client.post(path, headers=self.headers, json={'dns': ''})
            self.assertEqual(clear.status_code, 200, clear.json)
            self.assertIsNone(self.panel.find_iface(conf).dns)
            self.panel._copy_local_iface_from_parsed(iface, self.panel.find_iface(str(conf)))
            db.session.commit()
            self.assertEqual(self.client.get(path, headers=self.headers).json['dns'], '')

            def exported_dns():
                share = self.client.get('/s/interface-dns-test/links')
                self.assertEqual(share.status_code, 200, share.get_data(as_text=True))
                return parse_qs(urlsplit(share.get_data(as_text=True).strip()).query).get('dns')

            self.assertIsNone(exported_dns())
            config_path = f'/s/interface-dns-test/inbound/{subscription.links[0].id}/config'
            client_config = self.client.get(config_path)
            self.assertEqual(client_config.status_code, 200)
            self.assertNotIn(b'DNS = ', client_config.data)

            peer.dns = '9.9.9.9'
            db.session.commit()
            self.assertEqual(exported_dns(), ['9.9.9.9'])
            peer.dns = None
            db.session.commit()

            inherit = self.client.post(path, headers=self.headers, json={'dns': None})
            self.assertEqual(inherit.status_code, 200, inherit.json)
            self.assertIsNone(self.client.get(path, headers=self.headers).json['dns'])
            self.assertEqual(exported_dns(), ['1.0.0.1'])

    def test_bulk_subscription_purge_preserves_failed_node_and_snapshot_boundary(self):
        local, _ = self.add_irspeedy_interfaces()
        node = Node(name='Edge', base_url='https://node.example.test', api_key='node-key')
        admin = AdminAccount(username='purge-admin', password_hash='unused')
        db.session.add_all((node, admin))
        db.session.flush()
        node_id = node.id
        mirror = InterfaceConfig(
            name=f'n{node_id}:awg0', node=node, path='/etc/amnezia/amneziawg/awg0.conf',
            address='10.70.0.1/24', listen_port=51820, private_key='(remote)',
        )
        keys = [b64encode(bytes([i]) * 32).decode() for i in range(1, 5)]
        standalone = Peer(name='Standalone', iface=local, address='10.60.0.2/32',
                          public_key=keys[0], private_key=keys[0], status='online')
        remote = Peer(name='Remote', iface=mirror, address='10.70.0.2/32',
                      public_key=keys[1], private_key=keys[1])
        sub = Subscription(name='Node subscriber', token='bulk-purge-node')
        db.session.add_all((standalone, SubscriptionPeer(subscription=sub, peer=remote)))
        db.session.flush()
        db.session.add_all((PeerEvent(peer_id=standalone.id, event='created'),
                            ShortLink(peer_id=standalone.id, token='bulk-purge-shortlink')))
        db.session.commit()
        conf = Path(local.path)
        original = conf.read_text()

        def section(key):
            return f'\n[Peer]\nPublicKey = {key}\nAllowedIPs = 10.60.0.2/32\n'

        unmanaged = section(keys[2])
        late_block = section(keys[3])
        conf.write_text(original + section(keys[0]) + unmanaged + late_block)
        url = '/api/subscriptions/purge'
        with self.panel.app.app_context():
            self.assertEqual(self.client.get(url).status_code, 401)
        with self.client.session_transaction() as session:
            session['_user_id'] = str(admin.id)
            session['_fresh'] = True
        self.assertEqual(self.client.post(url, json={'confirmation': 'DELETE ALL'}).status_code, 400)

        jobs = []
        with (
            TemporaryDirectory() as directory,
            patch.object(self.panel, '_subscription_purge_state_file', return_value=Path(directory) / 'job.json'),
            patch.object(self.panel, '_ALLOC_LOCK_DIR', directory),
            patch.object(self.panel.csrf, 'protect'),
            patch.object(self.panel.threading, 'Thread', side_effect=lambda target, args, **kwargs:
                         SimpleNamespace(start=lambda: jobs.append((target, args)))),
            patch.object(self.panel.subprocess, 'check_output', return_value=''),
            patch.object(self.panel, 'node_post', side_effect=ConnectionError) as node_post,
        ):
            preview = self.client.get(url + '?preview=1').json['preview']
            self.assertEqual((preview['peers_total'], preview['subscriptions_total']), (2, 1))
            invalid = self.client.post(url, json={'preview': preview['token'], 'confirmation': 'DELETE'})
            self.assertEqual(invalid.status_code, 400)
            late = Peer(name='Late peer', iface=local, address='10.60.0.3/32',
                        public_key=keys[3], private_key=keys[3], status='online')
            db.session.add(late)
            db.session.commit()
            body = {'preview': preview['token'], 'confirmation': 'DELETE ALL'}
            self.assertEqual(self.client.post(url, json=body).status_code, 202)
            self.assertEqual(self.client.post(url, json=body).status_code, 409)
            self.assertEqual(self.client.get(url).json['job']['status'], 'running')

            target, args = jobs.pop()
            target(*args)
            db.session.remove()
            state = self.client.get(url).json['job']
            self.assertEqual(state['status'], 'partial', state)
            self.assertEqual(state['peers_removed'], 1)
            self.assertEqual(state['orphaned_peers_removed'], 0)
            self.assertEqual(state['remaining'], {'peers': 2, 'subscriptions': 1})
            self.assertEqual(state['failures'][0]['interface'], f'n{node_id}:awg0')
            self.assertEqual(conf.read_text(), original + unmanaged + late_block)
            self.assertEqual(ShortLink.query.count(), 0)
            self.assertEqual(PeerEvent.query.count(), 0)
            self.assertEqual({row.name for row in Peer.query}, {'Remote', 'Late peer'})

            node_post.side_effect = None
            node_post.return_value = {'ok': True, 'verified': 1}
            retry = self.client.get(url + '?preview=1').json['preview']
            self.assertEqual(self.client.post(url, json={
                'preview': retry['token'], 'confirmation': 'DELETE ALL',
            }).status_code, 202)
            target, args = jobs.pop()
            target(*args)
            db.session.remove()
            state = self.client.get(url).json['job']
            self.assertEqual(state['status'], 'complete', state)
            self.assertEqual(state['remaining'], {'peers': 0, 'subscriptions': 0})
            self.assertEqual(state['subscriptions_removed'], 1)
            self.assertEqual(SubscriptionPeer.query.count(), 0)
            self.assertEqual(conf.read_text().rstrip(), (original + unmanaged).rstrip())
            self.assertEqual(node_post.call_args.args[1:], ('/api/iface/awg0/peers/remove', {'public_keys': [keys[1]], 'blocked_addresses': ['10.70.0.2']}))

    def test_bulk_subscription_purge_clears_records_on_deleted_nodes(self):
        for index, name in ((1, 'awg0'), (2, 'awg100')):
            node = Node(name=f'Deleted {index}', base_url=f'https://edge{index}.example.test', api_key='unused')
            db.session.add(node)
            db.session.flush()
            iface = InterfaceConfig(
                name=f'n{node.id}:{name}', node=node, path=f'/etc/amnezia/amneziawg/{name}.conf',
                address='10.70.0.1/24', listen_port=51820, private_key='(remote)',
            )
            peer = Peer(name=f'Peer {index}', iface=iface, address='10.70.0.2/32',
                        public_key='unusable-legacy-key', private_key='fixture', status='offline')
            sub = Subscription(name=f'Client {index}', token=f'deleted-node-{index}')
            db.session.add(SubscriptionPeer(subscription=sub, peer=peer))
            db.session.flush()
            db.session.add_all((PeerEvent(peer_id=peer.id, event='created'),
                                ShortLink(peer_id=peer.id, token=f'deleted-peer-{index}')))
            db.session.commit()
            db.session.delete(node)
            db.session.commit()
            self.assertIsNone(iface.node_id)

        state = dict(id='test-purge', status='running', stage='starting',
                     peer_limit=db.session.query(self.panel.func.max(Peer.id)).scalar(),
                     subscription_limit=db.session.query(self.panel.func.max(Subscription.id)).scalar(),
                     peers_total=2, subscriptions_total=2, peers_removed=0, orphaned_peers_removed=0,
                     subscriptions_removed=0, failures=[])
        with (
            TemporaryDirectory() as directory,
            patch.object(self.panel, '_subscription_purge_state_file', return_value=Path(directory) / 'job.json'),
            patch.object(self.panel, '_ALLOC_LOCK_DIR', directory),
            patch.object(self.panel, '_purge_peer_runtime') as runtime,
        ):
            self.panel._run_subscription_purge(state, self.panel._subscription_purge_lock())
            job = self.panel._subscription_purge_status()
            runtime.assert_not_called()

        self.assertEqual(job['status'], 'complete')
        self.assertEqual(job['peers_removed'], 2)
        self.assertEqual(job['orphaned_peers_removed'], 2)
        self.assertEqual(job['subscriptions_removed'], 2)
        self.assertEqual(job['remaining'], {'peers': 0, 'subscriptions': 0})
        self.assertEqual(job['failures'], [])
        db.session.remove()
        self.assertEqual(SubscriptionPeer.query.count(), 0)
        self.assertEqual(ShortLink.query.count(), 0)
        self.assertEqual(PeerEvent.query.count(), 0)

    def test_node_client_dns_controls_exports_independently_from_agent_dns(self):
        node = Node(name='DNS node', base_url='https://node.example.test', api_key='node')
        admin = AdminAccount(username='node-dns-admin', password_hash='unused')
        db.session.add_all((node, admin))
        db.session.commit()
        base = f'/api/nodes/{node.id}'
        path = base + '/iface/awg0/client-dns'
        key = b64encode(b'a' * 32).decode()
        remote = {
            'name': 'awg0', 'address': '10.61.0.1/24', 'listen_port': 51820,
            'dns': '8.8.8.8', 'public_key': key,
        }

        def node_get(target, url, **kwargs):
            if url == '/api/interfaces':
                return {'interfaces': [remote], 'public_ipv4': '192.0.2.1'}
            if url == '/api/iface/awg0/available_ips':
                return {'available_ips': []}
            if url == '/api/iface/awg0/awg-parameters':
                return {'parameters': {'Jc': '4'}}
            self.fail(f'Unexpected Agent request {url}')

        with self.panel.app.app_context():
            self.assertEqual(self.client.put(path, json={'dns': ''}).status_code, 401)
        with self.client.session_transaction() as session:
            session['_user_id'] = str(admin.id)
            session['_fresh'] = True
        self.assertEqual(self.client.put(path, json={'dns': ''}).status_code, 400)

        with (
            patch.object(self.panel, 'node_get', side_effect=node_get) as read_node,
            patch.object(self.panel, 'node_post') as write_node,
            patch.object(self.panel, '_node_endpoint_fallback', return_value='node.example.test:51820'),
            patch.object(self.panel, '_panel_default_dns', return_value='1.0.0.1'),
            patch.object(self.panel.csrf, 'protect'),
        ):
            invalid = self.client.put(path, json={'dns': '9.9.9.9\nMTU = 576'})
            self.assertEqual(invalid.status_code, 400)
            read_node.assert_not_called()

            clear = self.client.put(path, json={'dns': ''})
            self.assertEqual(clear.status_code, 200, clear.json)
            mirror = InterfaceConfig.query.filter_by(node_id=node.id).one()
            self.assertEqual(mirror.dns, '8.8.8.8')

            # Subsequent inventory metadata may still contain a server-side DNS.
            remote['dns'] = '8.8.4.4'
            self.panel.ensure_node_mirror_iface(node, 'awg0', remote)
            self.assertEqual(mirror.dns, '8.8.4.4')
            peer = Peer(
                name='Node DNS test', iface=mirror, public_key=key, private_key=key,
                address='10.61.0.2/32', status='online',
            )
            sub = Subscription(name='Node DNS test', token='node-dns-test')
            link = SubscriptionPeer(subscription=sub, peer=peer)
            db.session.add(link)
            db.session.commit()

            def exported_dns():
                response = self.client.get('/s/node-dns-test/links')
                self.assertEqual(response.status_code, 200, response.json)
                return parse_qs(urlsplit(response.get_data(as_text=True).strip()).query).get('dns')

            def save(value):
                read_node.reset_mock()
                response = self.client.put(path, json={'dns': value})
                self.assertEqual(response.status_code, 200, response.json)
                read_node.assert_not_called()
                return response.json['dns']

            [interface] = self.client.get(base + '/interfaces').json['interfaces']
            self.assertEqual((interface['dns'], interface['client_dns']), ('8.8.4.4', ''))
            self.assertIsNone(exported_dns())
            config = self.client.get(f'/s/node-dns-test/inbound/{link.id}/config')
            self.assertEqual(config.status_code, 200)
            self.assertNotIn(b'DNS = ', config.data)

            self.assertIsNone(save(None))
            self.assertEqual(exported_dns(), ['1.0.0.1'])
            self.assertEqual(save('9.9.9.9، 149.112.112.112'), '9.9.9.9, 149.112.112.112')
            self.assertEqual(exported_dns(), ['9.9.9.9, 149.112.112.112'])
            peer.dns = '4.2.2.2'
            db.session.commit()
            self.assertEqual(exported_dns(), ['4.2.2.2'])
            write_node.assert_not_called()

    def test_interface_schema_keeps_existing_client_endpoints(self):
        local, _ = self.add_irspeedy_interfaces()
        iface_id = local.id
        db.session.remove()
        with db.engine.begin() as connection:
            connection.execute(text('ALTER TABLE interface_config DROP COLUMN endpoint_alternates, DROP COLUMN client_dns_override'))
        self.panel._interface_schema()
        self.panel._interface_schema()

        iface = db.session.get(InterfaceConfig, iface_id)
        self.assertEqual((iface.endpoint_host, iface.endpoint_port), ('wg0.example.test', 51820))
        self.assertIsNone(iface.endpoint_alternates)
        self.assertIsNone(iface.client_dns_override)

    def test_client_endpoint_pairs_expand_the_feed_for_local_and_node_peers(self):
        local, pinned = self.add_irspeedy_interfaces()
        node = Node(name='Edge', base_url='https://edge.example.test', api_key='node')
        db.session.add(node)
        db.session.commit()
        local_path = f'/api/iface/{local.id}/endpoint-default'
        node_path = f'/api/nodes/{node.id}/iface/awg0/endpoint-default'
        node_interface = {
            'name': 'awg0', 'address': '10.64.0.1/24', 'listen_port': 51825,
            'public_key': b64encode(bytes([72]) * 32).decode(),
        }

        def node_get(target, path, **kwargs):
            if path == '/api/interfaces':
                return {'interfaces': [node_interface]}
            if path == '/api/iface/awg0/awg-parameters':
                return {'parameters': {'Jc': '4'}}
            self.fail(f'Unexpected Agent request {path}')

        def save(path, hosts, ports):
            return self.client.put(path, headers=self.headers, json={'host': hosts, 'port': ports})

        def endpoints(response):
            self.assertEqual(response.status_code, 200, response.json)
            return [pair['endpoint'] for pair in response.json['client_endpoints']]

        with (
            patch.object(self.panel, 'node_get', side_effect=node_get),
            patch.object(self.panel, '_node_endpoint_fallback', return_value='auto.edge.test:51825'),
            patch.object(self.panel, '_endpoint_fallback', return_value='auto.example.test:51820'),
            patch.object(self.panel, '_wg_runtime_snapshot', return_value=({}, {})),
        ):
            self.assertEqual(endpoints(self.client.get(local_path, headers=self.headers)), ['wg0.example.test:51820'])
            self.assertEqual(endpoints(self.client.get(node_path, headers=self.headers)), [])
            local_endpoints = ['first.example.test:908', 'first.example.test:909', '[2001:db8::20]:910']
            self.assertEqual(endpoints(save(
                local_path, 'FIRST.example.test, first.example.test, [2001:0db8::20]', '908, 909, 910',
            )), local_endpoints)
            for hosts, ports, error in [
                ('first.example.test, second.example.test', 908, 'endpoint_count_mismatch'),
                ('first.example.test', '908, 909', 'endpoint_count_mismatch'),
                ('first.example.test,', '908, 909', 'endpoint_count_mismatch'),
                ('first.example.test, second.example.test', '908, 65536', 'endpoint_port_range'),
            ]:
                with self.subTest(hosts=hosts, ports=ports):
                    invalid = save(local_path, hosts, ports)
                    self.assertEqual(invalid.status_code, 400)
                    self.assertEqual(invalid.json['error'], error)
            self.assertEqual(endpoints(self.client.get(local_path, headers=self.headers)), local_endpoints)

            node_endpoints = ['192.0.2.3:808', '192.0.2.4:809']
            remote = save(node_path, '192.0.2.3، 192.0.2.4', '808، 809')
            self.assertEqual(endpoints(remote), node_endpoints)
            self.assertEqual(remote.json['listen_port'], 51825)
            self.assertEqual(endpoints(self.client.get(node_path, headers=self.headers)), node_endpoints)
            mirror = db.session.get(InterfaceConfig, remote.json['iface_id'])
            self.assertEqual(endpoints(save(
                f'/api/iface/{pinned.id}/endpoint-default', 'a.example.test, b.example.test', '200, 201',
            )), ['a.example.test:200', 'b.example.test:201'])
            sub = Subscription(name='Endpoint choices', token='endpoint-choices', data_limit_value=10)
            links = []
            for index, iface in enumerate((local, mirror, pinned)):
                key = b64encode(bytes([index + 1]) * 32).decode()
                address = f'{ip_interface(iface.address).ip + 1}/32'
                peer = Peer(
                    name=f'Peer {index}', iface=iface, private_key=key, public_key=key,
                    address=address, status='online',
                    endpoint='pinned.example.test:918' if iface is pinned else None,
                )
                link = SubscriptionPeer(subscription=sub, peer=peer, sort_order=index)
                db.session.add(link)
                links.append(link)
            db.session.commit()
            config_path = f'/s/endpoint-choices/inbound/{links[0].id}'

            def read_feed():
                feed = self.client.get('/s/endpoint-choices/links')
                self.assertEqual(feed.status_code, 200, feed.get_data(as_text=True))
                return [urlsplit(link) for link in feed.get_data(as_text=True).splitlines()]

            feed = read_feed()
            self.assertEqual([link.netloc for link in feed],
                             local_endpoints + node_endpoints + ['pinned.example.test:918'])
            self.assertEqual(len({link.query for link in feed[:3]}), 1)
            self.assertEqual(len({link.query for link in feed[3:5]}), 1)
            self.assertEqual(len({link.fragment for link in feed[:3]}), 3)
            self.assertEqual(Peer.query.count(), 3)
            self.assertEqual(Subscription.query.one().data_limit_value, 10)

            config = self.client.get(config_path + '/config').get_data(as_text=True)
            self.assertIn('Endpoint = first.example.test:908\n', config)
            with patch.object(self.panel.qrcode, 'make', wraps=self.panel.qrcode.make) as make_qr:
                self.assertEqual(self.client.get(config_path + '/qr').status_code, 200)
            make_qr.assert_called_once_with(config)
            portal_path = '/s/endpoint-choices'
            with patch.object(self.panel, '_public_host_peer', return_value=''):
                portal = self.client.get(portal_path)
                self.assertEqual(portal.status_code, 200)
                self.assertIn(b'[2001:db8::20]:910', portal.data)
                public = self.client.get(portal_path + '/api').json['subscription']
            self.assertEqual(len(public['locations']), 3)
            self.assertEqual([
                endpoint
                for loc in public['locations']
                for endpoint in [loc['endpoint'], *loc['alternate_endpoints']]
            ], [uri.netloc for uri in feed])

            query = urlencode({'endpoint': local_endpoints[2]})
            config_variant = self.client.get(config_path + '/config?' + query)
            self.assertEqual(config_variant.status_code, 200)
            expected = config.replace(local_endpoints[0], local_endpoints[2])
            self.assertEqual(config_variant.get_data(as_text=True), expected)
            with patch.object(self.panel.qrcode, 'make', wraps=self.panel.qrcode.make) as make_qr:
                self.assertEqual(self.client.get(config_path + '/qr?' + query).status_code, 200)
            make_qr.assert_called_once_with(expected)
            for action in ('config', 'qr'):
                self.assertEqual(self.client.get(
                    f'{config_path}/{action}?endpoint=example.test:999',
                ).status_code, 404)

            archive = self.client.get(portal_path + '/config')
            self.assertEqual(archive.status_code, 200)
            with ZipFile(BytesIO(archive.data)) as zipped:
                archive_endpoints = [
                    line.removeprefix('Endpoint = ')
                    for name in zipped.namelist()
                    for line in zipped.read(name).decode().splitlines()
                    if line.startswith('Endpoint = ')
                ]
            self.assertEqual(archive_endpoints, [uri.netloc for uri in feed])

            sub.enabled = False
            db.session.commit()
            public = self.client.get(portal_path + '/api').json['subscription']
            self.assertTrue(all(not loc['alternate_endpoints'] for loc in public['locations']))
            self.assertEqual(self.client.get(config_path + '/config?' + query).status_code, 403)
            sub.enabled = True
            db.session.commit()
            cleared = save(local_path, None, None)
            self.assertEqual(endpoints(cleared), [])
            self.assertEqual(cleared.json['endpoint_source'], 'auto')
            self.assertEqual([link.netloc for link in read_feed()],
                             ['auto.example.test:51820'] + node_endpoints + ['pinned.example.test:918'])

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
            self.assertEqual(capability.get_json()['max_local_targets'], 10)
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
            self.assertEqual(inventory.call_count, 2)
            self.assertEqual(install_local.call_count, 2)
            self.assertEqual(install_node.call_count, 3)

            feed = self.client.get(urlsplit(result.json['subscription']['feed_url']).path)
            self.assertEqual(feed.status_code, 200, feed.get_data(as_text=True))
            self.assertEqual([urlsplit(uri).netloc for uri in feed.get_data(as_text=True).splitlines()],
                             ['wg0.example.test:51820', 'wg1.example.test:51821',
                              '198.51.100.23:52611', '198.51.100.23:52612'])

    def test_irspeedy_all_adds_missing_node_once_to_an_existing_local_subscription(self):
        wg0, wg1 = self.add_irspeedy_interfaces()
        node = Node(name='Edge', base_url='https://node.example.test', api_key='node')
        db.session.add(node)
        db.session.commit()
        headers = {**self.headers, 'Idempotency-Key': '9' * 64}
        path = '/api/irspeedy/subscriptions'
        local_ids = [wg0.id, wg1.id]
        discovery_barrier = Barrier(2)
        remote = [{
            'name': 'wg0', 'address': '10.64.0.1/14', 'listen_port': 52611,
            'public_key': b64encode(bytes([72]) * 32).decode(),
        }]

        def node_get(target, url, **kwargs):
            if url == '/api/interfaces?fast=1':
                discovery_barrier.wait(timeout=10)
            if url in ('/api/interfaces?fast=1', '/api/interfaces'):
                return {'interfaces': remote}
            if url == '/api/health':
                return {'public_ipv4': '198.51.100.23'}
            if url.endswith('/awg-parameters'):
                return {'parameters': {'Jc': '4'}}
            self.fail(f'Unexpected Agent request {url}')

        with (
            patch.object(self.panel, 'node_get', side_effect=node_get),
            patch.object(self.panel, 'node_post', return_value={'host_cidr': '10.64.0.2/32'}) as install_node,
            patch.object(self.panel, 'install_local_peer') as install_local,
            patch.object(self.panel, '_wg_allowed_ips', return_value=set()),
            patch.object(self.panel, '_wg_runtime_snapshot', return_value=({}, {})),
            patch.object(self.panel.subprocess, 'check_output',
                         side_effect=[b64encode(bytes([n]) * 32) for n in range(1, 7)]),
        ):
            initial = self.client.post(path, headers=headers, json={
                'name': 'Existing client', 'time_limit_days': 7, 'data_limit_value': 10,
                'targets': [{'scope': 'local', 'iface_id': iface_id} for iface_id in local_ids],
            })
            self.assertEqual(initial.status_code, 201, initial.json)
            original = initial.json['subscription']
            self.assertEqual(original['interface_ids'], local_ids)
            sub = db.session.get(Subscription, original['id'])
            original_expiry = sub.expires_at
            original_peers = {link.peer_id: (link.peer.name, link.peer.public_key) for link in sub.links}
            db.session.remove()

            def retry():
                return self.panel.app.test_client().post(path, headers=headers, json={
                    'targets': 'all', 'name': 'New request', 'time_limit_days': 30, 'data_limit_value': 100,
                })

            with ThreadPoolExecutor(max_workers=2) as pool:
                responses = [pool.submit(retry) for _ in range(2)]
                results = [response.result(timeout=20) for response in responses]
            self.assertEqual([result.status_code for result in results], [200, 200],
                             [result.json for result in results])
            self.assertEqual(results[0].json, results[1].json)
            updated = results[0].json['subscription']
            self.assertEqual(updated['id'], original['id'])
            self.assertEqual(updated['feed_url'], original['feed_url'])
            self.assertEqual(updated['interface_ids'][:2], local_ids)
            self.assertEqual(len(updated['interface_ids']), 3)

            sub = db.session.get(Subscription, original['id'])
            self.assertEqual(Subscription.query.count(), 1)
            self.assertEqual(Peer.query.count(), 3)
            self.assertEqual(sub.expires_at, original_expiry)
            self.assertEqual(sub.data_limit_value, 10)
            self.assertEqual({link.peer_id: (link.peer.name, link.peer.public_key) for link in sub.links
                              if link.peer.iface_id in local_ids}, original_peers)
            self.assertEqual(install_local.call_count, 2)
            install_node.assert_called_once()

            feed = self.client.get(urlsplit(original['feed_url']).path)
            self.assertEqual(feed.status_code, 200, feed.get_data(as_text=True))
            self.assertEqual([urlsplit(uri).netloc for uri in feed.get_data(as_text=True).splitlines()],
                             ['wg0.example.test:51820', 'wg1.example.test:51821', '198.51.100.23:52611'])

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
