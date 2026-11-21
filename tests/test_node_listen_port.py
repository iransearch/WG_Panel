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
