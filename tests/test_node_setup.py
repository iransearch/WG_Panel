import json
import os
import queue
import socket
import threading
from contextlib import contextmanager
from unittest.mock import MagicMock, Mock, patch

import paramiko
import pytest

from panel_core import node_setup


def settings():
    return node_setup.parse_settings({
        "ip": "1.1.1.1",
        "username": "root",
        "password": "test-only password",
        "domain": "Node.Example.com.",
        "email": "admin@example.com",
    })


def test_settings_default_ports_and_rejects_private_targets():
    config, password = settings()
    assert config["base_url"] == "https://node.example.com:8443"
    assert config["awg_port"] == 51820
    assert "password" not in config
    assert password == "test-only password"
    with pytest.raises(node_setup.SetupError, match="public server IP"):
        node_setup.parse_settings({**config, "ip": "169.254.169.254", "password": password})


def test_job_claim_and_password_handoff(tmp_path):
    config, password = settings()
    process = MagicMock()
    locks = []

    def launch(*args, **kwargs):
        assert password not in str(args)
        assert typed_state()["status"] == "pending"
        locks.extend(kwargs["pass_fds"])
        # Simulate the subprocess inheriting copies of all claims.
        for index, fd in enumerate(locks):
            locks[index] = os.dup(fd)
        return process

    def typed_state():
        return json.loads(next(tmp_path.glob("*.json")).read_text())

    with patch.object(node_setup.subprocess, "Popen", side_effect=launch):
        job = node_setup.enqueue(tmp_path, config, password)
        try:
            process.stdin.write.assert_called_once_with(password.encode())
            assert password not in json.dumps(typed_state())
            assert node_setup.list_jobs(tmp_path)[0]["status"] == "pending"
            with pytest.raises(node_setup.SetupConflict):
                node_setup.enqueue(tmp_path, {**config, "domain": "second.example.com"}, password)
        finally:
            for fd in locks:
                os.close(fd)
    assert node_setup.list_jobs(tmp_path)[0]["id"] == job["id"]
    assert typed_state()["status"] == "failed"


@contextmanager
def ssh_server(listener, host_key):
    authenticated = queue.Queue()
    active = threading.Event()

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            authenticated.put((username, password))
            return paramiko.AUTH_SUCCESSFUL

    def serve():
        connection, _ = listener.accept()
        with paramiko.Transport(connection) as transport:
            transport.add_server_key(host_key)
            try:
                transport.start_server(server=Server())
                active.wait(5)
            except (paramiko.SSHException, EOFError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield authenticated
    finally:
        active.set()
        thread.join(7)


def test_ssh_first_key_is_pinned_and_changed_key_never_receives_password(tmp_path):
    config, password = settings()
    config["ip"] = "127.0.0.1"
    with socket.socket() as listener:
        listener.bind((config["ip"], 0))
        listener.listen()
        config["ssh_port"] = listener.getsockname()[1]
        original = paramiko.RSAKey.generate(2048)
        with ssh_server(listener, original) as authenticated:
            with node_setup._connect_ssh(config, password, tmp_path):
                assert authenticated.get(timeout=2) == ("root", password)
        assert next(tmp_path.glob("*.known_hosts")).stat().st_mode & 0o777 == 0o600
        with ssh_server(listener, original):
            with node_setup._connect_ssh(config, password, tmp_path):
                pass
        with ssh_server(listener, paramiko.RSAKey.generate(2048)) as authenticated:
            with pytest.raises(node_setup.SetupError, match="host key has changed"):
                node_setup._connect_ssh(config, password, tmp_path)
            assert authenticated.empty()


@pytest.mark.parametrize("verified", [True, False])
def test_registers_only_after_healthy_https(tmp_path, monkeypatch, verified):
    from io import StringIO

    from panel_core import node_registry

    config, password = settings()
    path = tmp_path / "job.json"
    node_setup._write_state(path, {"settings": config, "status": "pending", "stage": "queued"})
    monkeypatch.setattr("sys.stdin", StringIO(password))
    monkeypatch.setattr(node_setup, "_check_dns", Mock())
    monkeypatch.setattr(node_setup, "_connect_ssh", Mock(return_value=MockSSH()))
    monkeypatch.setattr(node_setup, "_install", Mock(return_value="A" * 24))
    verify = Mock(side_effect=None if verified else node_setup.SetupError("HTTPS verification failed"))
    monkeypatch.setattr(node_setup, "_verify_node", verify)
    register = Mock(return_value=23)
    monkeypatch.setattr(node_registry, "register_provisioned_node", register)

    node_setup._run_job(path)

    job = json.loads(path.read_text())
    assert password not in path.read_text()
    if verified:
        assert job["status"] == "done"
        assert job["node_id"] == 23
        register.assert_called_once_with(config["name"], config["base_url"], "A" * 24)
    else:
        assert job["status"] == "failed"
        assert "HTTPS verification failed" in job["message"]
        register.assert_not_called()


class MockSSH:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass
