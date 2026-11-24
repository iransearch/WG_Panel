import ipaddress
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
    assert config["interface_name"] == "awg0"
    network = ipaddress.IPv4Interface(config["interface_address"]).network
    assert network.num_addresses - 3 == 262141
    assert "password" not in config
    assert password == "test-only password"
    with pytest.raises(node_setup.SetupError, match="public server IP"):
        node_setup.parse_settings({**config, "ip": "169.254.169.254", "password": password})


def test_custom_interface_name_and_private_cidr_reach_the_installer(monkeypatch):
    config, password = settings()
    config, _ = node_setup.parse_settings({
        **config, "password": password, "interface_name": "wg1", "interface_address": "172.24.3.1/16",
    })
    commands = []

    def run(client, argv, *, password=None, on_line=None, on_stderr=None, timeout=25):
        commands.append(argv)
        on_line(b"0" if argv == ["id", "-u"] else b"WG_API_KEY:" + b"A" * 24)
        return 0

    monkeypatch.setattr(node_setup, "_ssh_run", run)
    assert node_setup._install(None, config, password, lambda name: None) == "A" * 24
    assert commands[-1][-2:] == ["wg1", "172.24.3.1/16"]

    for fields in [
        {"interface_name": "../wg1"},
        {"interface_address": "172.20.0.1/8"},
        {"interface_address": "1.1.1.1/14"},
        {"interface_address": "10.64.0.0/14"},
    ]:
        with pytest.raises(node_setup.SetupError):
            node_setup.parse_settings({**config, "password": password, **fields})


def test_ssh_reader_captures_split_stdout_stderr_and_bounds_lines():
    stdout_chunks = [b"WG_STAGE:depend", b"encies\n", b"x" * 8193, b"overflow suffix\nlast stdout"]
    stderr_chunks = [b"E: Could not", b" resolve mirror\nlast stderr"]
    session = MagicMock()
    session.__enter__.return_value = session
    session.recv_ready.side_effect = lambda: bool(stdout_chunks)
    session.recv.side_effect = lambda _: stdout_chunks.pop(0)
    session.recv_stderr_ready.side_effect = lambda: bool(stderr_chunks)
    session.recv_stderr.side_effect = lambda _: stderr_chunks.pop(0)
    session.exit_status_ready.return_value = True
    session.recv_exit_status.return_value = 100
    client = MagicMock()
    client.get_transport.return_value.open_session.return_value = session
    stdout, stderr = [], []

    code = node_setup._ssh_run(client, ["apt-get", "update"], on_line=stdout.append,
                               on_stderr=stderr.append)
    assert code == 100
    assert stdout == [b"WG_STAGE:dependencies", b"[installer line exceeded 8 KiB]", b"last stdout"]
    assert stderr == [b"E: Could not resolve mirror", b"last stderr"]


def test_failed_setup_persists_redacted_command_and_original_error(tmp_path, monkeypatch):
    from io import StringIO

    config, password = settings()
    api_key = "AB" * 12
    path = tmp_path / "job.json"
    node_setup._write_state(path, {"settings": config, "status": "pending", "stage": "queued"})
    monkeypatch.setattr("sys.stdin", StringIO(password))
    monkeypatch.setattr(node_setup, "_check_dns", Mock())
    monkeypatch.setattr(node_setup, "_connect_ssh", Mock(return_value=MockSSH()))

    def run(client, argv, *, password=None, on_line=None, on_stderr=None, timeout=25):
        if argv == ["id", "-u"]:
            on_line(b"0")
            return 0
        on_line(b"WG_STAGE:dependencies")
        on_line(b"WG_STEP:apt-get update")
        for _ in range(40):
            on_line(b"Old progress message")
        on_line(f"Installer read {api_key}".encode())
        on_line(b"WG_API_KEY:" + api_key.encode())
        on_stderr(b"\x1b[31mE: Could not resolve mirror.example.test\x1b[0m")
        on_stderr(f"Retrying with {settings()[1]}".encode())
        on_stderr(b"Authorization: Bearer header-key")
        on_stderr(b"https://build:private-pass@mirror.example.test/path?access_token=private-token")
        return 100

    monkeypatch.setattr(node_setup, "_ssh_run", run)
    node_setup._run_job(path)
    serialized = path.read_text()
    job = json.loads(serialized)
    assert job["stage"] == "dependencies"
    assert job["status"] == "failed"
    assert job["message"] == "The installer exited with code 100."
    details = job["diagnostics"]
    assert details["step"] == "apt-get update"
    assert details["exit_code"] == 100
    assert "E: Could not resolve mirror.example.test" in details["output"]
    assert len(details["output"]) == 32
    for secret in (password, api_key, "header-key", "private-pass", "private-token"):
        assert secret not in serialized


def test_health_checks_the_requested_interface_and_address(monkeypatch):
    config, _ = settings()
    config.update(interface_name="wg1", interface_address="172.24.3.1/16")
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    pool = MagicMock()
    pool.__enter__.return_value.request.return_value = response
    monkeypatch.setattr(node_setup.urllib3, "HTTPSConnectionPool", lambda *args, **kwargs: pool)
    monkeypatch.setattr(node_setup, "_check_dns", lambda settings: None)
    monkeypatch.setattr(node_setup.time, "sleep", lambda seconds: None)

    def health(name, address):
        response.read.return_value = json.dumps({
            "ok": True, "interfaces": [{"name": name, "address": address, "is_up": True}],
        }).encode()

    health("awg0", "172.24.3.1/16")
    with pytest.raises(node_setup.SetupError, match="wg1"):
        node_setup._verify_node(config, "A" * 24)
    health("wg1", "10.10.10.1/24")
    with pytest.raises(node_setup.SetupError, match="wg1") as failure:
        node_setup._verify_node(config, "A" * 24)
    assert "reported address 10.10.10.1/24" in failure.value.diagnostics["output"][0]
    health("wg1", "172.24.3.1/16")
    node_setup._verify_node(config, "A" * 24)


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
            except (paramiko.SSHException, EOFError, ConnectionResetError):
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
