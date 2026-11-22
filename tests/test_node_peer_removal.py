import subprocess

import pytest

from agent import node_agent


PEER_KEY = "/" + "A" * 38 + "//AA="
OTHER_KEY = "B" * 43 + "="
INTERFACE = "[Interface]\nAddress = 10.64.0.1/14\nListenPort = 51820\n"


@pytest.fixture
def node(tmp_path, monkeypatch):
    monkeypatch.setattr(node_agent, "WG_CONF_PATH", str(tmp_path))
    monkeypatch.setattr(node_agent, "API_KEY", "test-node-key")
    kept_peer = f"[Peer]\nPublicKey = {OTHER_KEY}\nAllowedIPs = 10.64.0.3/32\n"
    config = tmp_path / "awg0.conf"
    config.write_text(INTERFACE + f"[Peer]\nPublicKey = {PEER_KEY} # client\nAllowedIPs = 10.64.0.2/32\n" + kept_peer)

    def delete(path="/api/peer", payload=None):
        return node_agent.app.test_client().delete(
            path, json={"public_key": PEER_KEY} if payload is None else payload,
            headers={"Authorization": "Bearer test-node-key"},
        )

    return config, kept_peer, delete


def test_peer_with_slashes_removes_runtime_and_config_and_can_be_retried(node, monkeypatch):
    config, kept_peer, delete = node
    config.with_name("awg1.conf").write_text(INTERFACE + f"[Peer]\nPublicKey = {PEER_KEY}\n")
    active_keys = [PEER_KEY, OTHER_KEY]
    removals = []

    def show(command, **kwargs):
        if command == ["awg", "show", "interfaces"]:
            return b"awg0\n"
        assert command == ["awg", "show", "awg0", "peers"]
        return ("\n".join(active_keys) + "\n").encode()

    def remove(command, **kwargs):
        removals.append(command)
        active_keys.remove(command[4])

    monkeypatch.setattr(node_agent.subprocess, "check_output", show)
    monkeypatch.setattr(node_agent.subprocess, "run", remove)

    assert delete().json == {
        "ok": True, "public_key": PEER_KEY, "runtime_removed": True, "config_removed": True,
    }
    assert delete().status_code == 200
    assert removals == [["awg", "set", "awg0", "peer", PEER_KEY, "remove"]]
    assert config.read_text() == INTERFACE + kept_peer
    assert config.with_name("awg1.conf").read_text() == INTERFACE


def test_runtime_error_preserves_the_config_and_reports_failure(node, monkeypatch):
    config, _, delete = node
    original = config.read_text()

    def show(command, **kwargs):
        if command == ["awg", "show", "interfaces"]:
            return b"awg0\n"
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(node_agent.subprocess, "check_output", show)
    assert delete(payload={"public_key": "invalid"}).status_code == 400
    response = delete()
    assert response.status_code == 502
    assert response.json["ok"] is False
    assert config.read_text() == original


def test_legacy_delete_route_remains_available(node, monkeypatch):
    config, _, delete = node
    monkeypatch.setattr(node_agent.subprocess, "check_output", lambda *args, **kwargs: b"")
    assert delete(path=f"/api/peer/{OTHER_KEY}").status_code == 200
    assert OTHER_KEY not in config.read_text()
    assert PEER_KEY in config.read_text()
