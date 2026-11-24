import subprocess
from unittest.mock import Mock, call

import pytest

from agent import node_agent


CONFIG = """[Interface]
Address = 10.10.10.1/24
PrivateKey = fixture
ListenPort = 51820 # client UDP
PostUp = echo up

[Peer]
PublicKey = peer-fixture
AllowedIPs = 10.10.10.2/32
"""


@pytest.fixture
def node(tmp_path, monkeypatch):
    monkeypatch.setattr(node_agent, "WG_CONF_PATH", str(tmp_path))
    monkeypatch.setattr(node_agent, "API_KEY", "test-node-key")
    monkeypatch.setenv("WG_NODE_OPS_STATE_DIR", str(tmp_path / "operations"))
    monkeypatch.setattr(node_agent, "_pubkey_from_priv", lambda key: "fixture-public")
    config = tmp_path / "awg0.conf"
    config.write_text(CONFIG)
    client = node_agent.app.test_client()

    def save(port):
        return client.post(
            "/api/iface/awg0/listen-port",
            json={"listen_port": port},
            headers={"Authorization": "Bearer test-node-key"},
        )

    return client, config, save


@pytest.mark.parametrize("fast", [False, True])
def test_interface_inventory_accepts_a_config_file_path(node, monkeypatch, fast):
    client, config, _ = node
    monkeypatch.setattr(node_agent, "WG_CONF_PATH", str(config))
    monkeypatch.setattr(node_agent, "_iface_up", lambda name: True)
    monkeypatch.setattr(node_agent, "_private_networks", lambda: [])
    monkeypatch.setattr(node_agent, "_public_ipv4", lambda: "192.0.2.1")
    monkeypatch.setattr(node_agent, "_extract_wgip", lambda name, network: set())

    response = client.get(
        "/api/interfaces",
        query_string={"fast": int(fast)},
        headers={"Authorization": "Bearer test-node-key"},
    )

    assert response.status_code == 200
    [iface] = response.json["interfaces"]
    assert iface["name"] == "awg0"
    assert iface["listen_port"] == 51820
    assert iface["available_ips"][:1] == ([] if fast else ["10.10.10.3/24"])


def test_peer_provisioning_accepts_a_config_file_path(node, monkeypatch):
    client, config, _ = node
    monkeypatch.setattr(node_agent, "WG_CONF_PATH", str(config))
    monkeypatch.setattr(node_agent, "_extract_wgip", lambda name, network: set())
    monkeypatch.setattr(node_agent, "_runtime_has_peer", lambda iface, key: True)
    monkeypatch.setattr(node_agent.subprocess, "check_call", lambda *args, **kwargs: 0)
    runtime = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(node_agent.subprocess, "run", runtime)
    headers = {"Authorization": "Bearer test-node-key"}

    response = client.get("/api/iface/awg0/available_ips", headers=headers)
    assert response.status_code == 200
    assert response.json["available_ips"][0] == "10.10.10.3/24"

    response = client.post(
        "/api/peers/add", json={"iface": "awg0", "public_key": "client-fixture"}, headers=headers,
    )

    assert response.status_code == 200
    assert response.json["host_cidr"] == "10.10.10.3/32"
    assert "PublicKey = client-fixture\nAllowedIPs = 10.10.10.3/32" in config.read_text()
    runtime.assert_called_once()


@pytest.mark.parametrize("is_up", [False, True])
def test_persists_only_interface_port_and_updates_live_interface(node, monkeypatch, is_up):
    _, config, save = node
    monkeypatch.setattr(node_agent, "_iface_up", lambda name: is_up)
    runtime = Mock(return_value=subprocess.CompletedProcess([], 0, stdout="51820\n"))
    monkeypatch.setattr(node_agent.subprocess, "run", runtime)

    response = save(51821)

    assert response.status_code == 200
    assert response.json == {"ok": True, "listen_port": 51821, "is_up": is_up, "changed": True}
    assert config.read_text() == CONFIG.replace("51820", "51821")
    assert node_agent._read_iface(config)["listen_port"] == 51821
    if is_up:
        assert [called.args[0] for called in runtime.call_args_list] == [
            ["awg", "show", "awg0", "listen-port"],
            ["awg", "set", "awg0", "listen-port", "51821"],
        ]
    else:
        runtime.assert_not_called()


def test_duplicate_port_or_bad_input_does_not_change_config(node, monkeypatch):
    client, config, save = node
    config.with_name("awg1.conf").write_text(CONFIG.replace("51820", "51821"))
    monkeypatch.setattr(node_agent, "_iface_up", lambda name: False)
    assert client.post("/api/iface/awg0/listen-port", json={"listen_port": 51821}).status_code == 401
    assert save(0).status_code == 400
    assert save(True).status_code == 400
    assert save(51821.5).status_code == 400
    assert save(51821).json["error"] == "listen_port_in_use"
    assert config.read_text() == CONFIG


@pytest.mark.parametrize("write_fails", [False, True])
def test_failed_port_change_keeps_config_and_restores_runtime(node, monkeypatch, write_fails):
    _, config, save = node
    monkeypatch.setattr(node_agent, "_iface_up", lambda name: True)
    runtime = Mock(return_value=subprocess.CompletedProcess([], 0, stdout="51819\n"))
    monkeypatch.setattr(node_agent.subprocess, "run", runtime)
    bind_error = subprocess.CalledProcessError(1, "awg", stderr="Address already in use")
    set_port = Mock(side_effect=None if write_fails else [bind_error, None])
    monkeypatch.setattr(node_agent, "_set_listen_port", set_port)
    if write_fails:
        monkeypatch.setattr(node_agent, "_write_conf_atomic", Mock(side_effect=OSError("disk full")))

    response = save(51821)

    assert response.status_code == (500 if write_fails else 409)
    assert set_port.call_args_list == [call("awg0", 51821), call("awg0", 51819)]
    assert config.read_text() == CONFIG


def test_peer_batch_removes_only_targeted_live_and_persisted_peers(node, monkeypatch):
    from base64 import b64encode

    client, config, _ = node
    first, second, untouched = [b64encode(bytes([i]) * 32).decode() for i in (1, 2, 3)]
    other = config.with_name('awg1.conf')
    other.write_text(CONFIG.replace('peer-fixture', first))
    base = CONFIG.split('[Peer]')[0]
    blocks = {key: f'[Peer] # client\nPublicKey = {key} # key\nAllowedIPs = 10.1.1.2/32\n'
              for key in (first, second, untouched)}
    config.write_text(base + ''.join(blocks.values()))
    read_runtime = Mock(side_effect=[
        'awg0 awg1\n', f'{first}\n{second}\n{untouched}\n', untouched,
        '[{"dst":"10.1.1.2"},{"dst":"10.1.1.3"},{"dst":"10.1.0.0/16"}]',
    ])
    monkeypatch.setattr(node_agent.subprocess, 'check_output', read_runtime)
    run = Mock()
    monkeypatch.setattr(node_agent.subprocess, 'run', run)
    url = '/api/iface/awg0/peers/remove'
    payload = {'public_keys': [first, second], 'blocked_addresses': ['10.1.1.2']}
    headers = {'Authorization': 'Bearer test-node-key'}

    assert client.post(url, json=payload).status_code == 401
    assert client.post(url, json={'public_keys': ['bad']}, headers=headers).status_code == 400
    response = client.post(url, json=payload, headers=headers)

    assert response.status_code == 200
    assert response.json['verified'] == 2
    assert run.call_count == 2
    remove, routes = run.call_args_list
    assert remove.args[0] == ['awg', 'set', 'awg0', 'peer', first, 'remove', 'peer', second, 'remove']
    assert routes.args[0] == ['ip', '-4', '-batch', '-']
    assert routes.kwargs['input'] == 'route del blackhole 10.1.1.2/32\n'
    assert config.read_text() == base + blocks[untouched]
    assert first in other.read_text()
