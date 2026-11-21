"""Background jobs for installing a remote node over SSH."""
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import select
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

import requests
import urllib3


PROVISION = r"""
set -eu
root=/opt/wg-panel-node
. /etc/os-release
if [ "${ID:-}" != debian ] && [ "${ID:-}" != ubuntu ] || [ ! -d /run/systemd/system ]; then
    echo WG_ERROR:platform
    exit 1
fi
if systemctl cat wg-panel.service >/dev/null 2>&1; then
    echo WG_ERROR:panel
    exit 1
fi
if [ ! -f "$root/.panel-provision-repo" ]; then
    if [ -e "$root" ]; then
        echo WG_ERROR:existing
        exit 1
    fi
    staging=$(mktemp -d /opt/wg-panel-node.XXXXXX)
    trap 'rm -rf -- "$staging"' EXIT
    export DEBIAN_FRONTEND=noninteractive GIT_TERMINAL_PROMPT=0 NEEDRESTART_MODE=a
    apt-get update && apt-get install -y git ca-certificates python3 || exit 1
    git clone --depth 1 --branch main https://github.com/iransearch/WG_Panel.git "$staging"
    touch "$staging/.panel-provision-repo"
    mv -T "$staging" "$root"
fi
exec python3 "$root/agent/node_provision.py" "$@"
"""

STATUSES = {
    "ssh": "Connecting to the server over SSH",
    "dns": "Checking the domain’s DNS records",
    "bootstrap": "Preparing the server and downloading the node installer",
    "dependencies": "Installing node dependencies",
    "interface": "Setting up AmneziaWG",
    "certificate": "Issuing the Let’s Encrypt certificate",
    "service": "Starting the node agent",
    "health": "Verifying the HTTPS node API and interface",
    "register": "Adding the node to the panel",
}
REMOTE_ERRORS = {
    "existing": "An existing node installation was found. Use Add node to connect it.",
    "platform": "The target must run Debian or Ubuntu with systemd.",
    "panel": "WG Panel is already installed on this server. Choose a separate server for the node.",
    "settings": "This server was already set up with different node settings.",
    "port80": "Port 80 is in use. Free it for the standalone certificate challenge.",
    "api_port": "The node API TCP port is already in use.",
    "awg_port": "The AmneziaWG UDP port is already in use.",
    "network": "The default AmneziaWG subnet overlaps an existing server route.",
    "certificate": "Certificate issuance failed. Check DNS and inbound TCP port 80.",
}
REMOTE_STAGES = {"dependencies", "interface", "certificate", "service"}
ACTIVE = {"pending", "running"}
DEFAULT_NODE_PORT = 8443
DEFAULT_AWG_PORT = 51820


class SetupError(Exception):
    pass


class SetupConflict(SetupError):
    pass


def parse_settings(payload):
    if not isinstance(payload, dict):
        raise SetupError("Enter the node settings.")

    def field(name):
        value = payload.get(name, "")
        return value.strip() if isinstance(value, str) else ""

    try:
        ip = ipaddress.ip_address(field("ip"))
        if not ip.is_global or ip.is_multicast or "%" in str(ip):
            raise ValueError()
    except ValueError:
        raise SetupError("Enter a public server IP address.") from None

    username = field("username")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username):
        raise SetupError("Enter a valid SSH username.")

    try:
        domain = field("domain").rstrip(".").encode("idna").decode().lower()
    except UnicodeError:
        raise SetupError("Enter a valid domain.") from None
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(domain) > 240 or not re.fullmatch(rf"(?:{label}\.)+{label}", domain):
        raise SetupError("Enter a fully qualified domain.")
    if domain.rsplit(".", 1)[1].isdigit():
        raise SetupError("Enter a domain instead of an IP address.")

    email = field("email")
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise SetupError("Enter a valid Let’s Encrypt email address.")

    ports = {}
    for key, default in (("ssh_port", 22), ("node_port", DEFAULT_NODE_PORT), ("awg_port", DEFAULT_AWG_PORT)):
        raw = payload.get(key)
        if raw is None or raw == "":
            raw = default
        if not re.fullmatch(r"[0-9]{1,5}", str(raw)) or not 1 <= int(raw) <= 65535:
            raise SetupError("Enter port numbers between 1 and 65535.")
        ports[key] = int(raw)
    if ports["node_port"] in (80, ports["ssh_port"]):
        raise SetupError("Choose a node API port different from port 80 and the SSH port.")

    name = field("name") or domain[:64]
    if len(name) > 64 or any(ord(char) < 32 for char in name):
        raise SetupError("Enter a node name of up to 64 characters.")
    password = payload.get("password")
    if (not isinstance(password, str) or not password
            or len(password.encode("utf-8", errors="replace")) > 1024
            or any(char in password for char in "\r\n\0")):
        raise SetupError("Enter a valid SSH password.")
    base_url = "https://" + domain
    if ports["node_port"] != 443:
        base_url += f":{ports['node_port']}"
    settings = dict(name=name, ip=str(ip), username=username, domain=domain,
                    email=email, base_url=base_url, **ports)
    return settings, password


def _write_state(path, state):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        scratch = Path(stream.name)
        try:
            json.dump(state, stream)
            stream.close()
            scratch.replace(path)
        finally:
            scratch.unlink(missing_ok=True)


def _lock(stack, path):
    stream = stack.enter_context(path.open("a"))
    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return stream.fileno()


def enqueue(directory, settings, password):
    try:
        import paramiko  # noqa: F401
    except ImportError:
        raise SetupError("Install the panel’s updated Python requirements to enable SSH setup.") from None

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex
    path = directory / (job_id + ".json")
    locks = [directory / (job_id + ".lock")]
    for field in ("ip", "domain"):
        digest = hashlib.sha256(settings[field].encode()).hexdigest()
        locks.append(directory / f"{field}-{digest}.lock")
    state = dict(id=job_id, settings=settings, status="pending", stage="queued",
                 message="Waiting for the installer", updated_at=time.time())

    with ExitStack() as stack:
        try:
            fds = [_lock(stack, path) for path in locks]
        except BlockingIOError:
            raise SetupConflict("A setup is already running for this server or domain.") from None

        _write_state(path, state)
        try:
            # The child inherits the locks across the handoff. Only the pipe carries the password.
            process = subprocess.Popen(
                [sys.executable, "-m", "panel_core.node_setup", str(path)],
                cwd=Path(__file__).resolve().parents[1],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=tuple(fds), start_new_session=True,
            )
            with process.stdin:
                process.stdin.write(password.encode())
        except (OSError, UnicodeError):
            state.update(status="failed", message="Could not start the background installer.")
            _write_state(path, state)
    return state


def list_jobs(directory):
    jobs = []
    paths = sorted(directory.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    for path in paths[:30]:
        with path.open(encoding="utf-8") as stream:
            state = json.load(stream)
        if state["status"] in ACTIVE:
            with ExitStack() as stack:
                try:
                    _lock(stack, path.with_suffix(".lock"))
                except BlockingIOError:
                    pass
                else:
                    # Re-read after obtaining the lock in case the worker just finished.
                    with path.open(encoding="utf-8") as stream:
                        state = json.load(stream)
                    if state["status"] in ACTIVE:
                        state.update(status="failed", message="Setup was interrupted. Retry to resume on the server.")
                        _write_state(path, state)
        jobs.append(state)
    return jobs


def _check_dns(settings):
    try:
        addresses = {ipaddress.ip_address(result[4][0]) for result in
                     socket.getaddrinfo(settings["domain"], 80, type=socket.SOCK_STREAM)}
    except OSError:
        addresses = set()
    if addresses != {ipaddress.ip_address(settings["ip"])}:
        raise SetupError("Point the domain directly to the server IP. Check its A and AAAA records and disable DNS proxying.")


def _connect_ssh(settings, password, directory):
    import paramiko

    ip, port = settings["ip"], settings["ssh_port"]
    host_id = ip if port == 22 else f"[{ip}]:{port}"
    digest = hashlib.sha256(host_id.encode()).hexdigest()
    known_hosts = directory / f"ssh-{digest}.known_hosts"

    class RememberHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            client.get_host_keys().add(hostname, key.get_name(), key)
            # Per-IP setup locks serialize writes, including the first connection.
            with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=directory, delete=False) as stream:
                scratch = Path(stream.name)
                try:
                    stream.write(f"{hostname} {key.get_name()} {key.get_base64()}\n")
                    stream.close()
                    scratch.replace(known_hosts)
                finally:
                    scratch.unlink(missing_ok=True)

    client = paramiko.SSHClient()
    try:
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(RememberHostKey())
        client.connect(ip, port=port, username=settings["username"], password=password,
                       allow_agent=False, look_for_keys=False, timeout=10,
                       banner_timeout=15, auth_timeout=15, channel_timeout=15)
        return client
    except paramiko.BadHostKeyException:
        client.close()
        raise SetupError("The server’s SSH host key has changed. Verify the server identity before retrying.") from None
    except paramiko.AuthenticationException:
        client.close()
        raise SetupError("SSH authentication failed. Check the username and password.") from None
    except (OSError, paramiko.SSHException):
        client.close()
        raise SetupError("Could not connect over SSH. Check the IP, port and server firewall.") from None


def _ssh_run(client, argv, *, password=None, on_line=None, timeout=25):
    channel = client.get_transport().open_session(timeout=15)
    with channel:
        channel.settimeout(15)
        channel.exec_command(shlex.join(argv))
        if password is not None:
            channel.sendall((password + "\n").encode())
        channel.shutdown_write()

        # Drain both streams to keep SSH flow control moving. Keep arbitrary
        # installer output out of the job response and panel logs.
        output = bytearray()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if channel.recv_stderr_ready():
                channel.recv_stderr(32768)
            if channel.recv_ready():
                output.extend(channel.recv(32768))
                while (newline := output.find(b"\n")) >= 0:
                    line = bytes(output[:newline]).strip()
                    del output[:newline + 1]
                    if on_line:
                        on_line(line)
                if len(output) > 8192:
                    output.clear()
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                if output and on_line:
                    on_line(bytes(output).strip())
                return channel.recv_exit_status()
            if not channel.recv_ready() and not channel.recv_stderr_ready():
                select.select([channel], [], [], 0.2)
    raise SetupError("The SSH installer timed out.")


def _install(client, settings, password, stage):
    uid = []
    if _ssh_run(client, ["id", "-u"], on_line=uid.append) != 0:
        raise SetupError("Could not check the SSH user’s privileges.")
    sudo, secret = [], None
    if uid != [b"0"]:
        sudo = ["sudo", "-n", "--"]
        if _ssh_run(client, [*sudo, "true"]) != 0:
            sudo, secret = ["sudo", "-S", "-p", "", "--"], password
            if _ssh_run(client, [*sudo, "true"], password=secret) != 0:
                raise SetupError("The SSH user must be root or have sudo access with its SSH password.")

    api_keys, errors = [], []

    def monitor(line):
        if line.startswith(b"WG_STAGE:"):
            name = line[9:].decode("ascii", errors="ignore")
            if name in REMOTE_STAGES:
                stage(name)
        elif line.startswith(b"WG_ERROR:"):
            errors.append(REMOTE_ERRORS.get(line[9:].decode("ascii", errors="ignore")))
        elif re.fullmatch(rb"WG_API_KEY:[A-Za-z0-9_-]{24}", line):
            api_keys.append(line[11:].decode("ascii"))

    command = [
        *sudo, "flock", "-n", "-E", "73", "/run/lock/wg-panel-node-setup.lock",
        "bash", "-c", PROVISION, "node-setup", settings["domain"], settings["email"],
        str(settings["node_port"]), str(settings["awg_port"]), settings["ip"],
    ]
    code = _ssh_run(client, command, password=secret, on_line=monitor, timeout=2700)
    if code == 73:
        raise SetupError("A setup is already running on the server.")
    if code != 0 or len(api_keys) != 1:
        raise SetupError(next((error for error in errors if error), "The installer failed during this step. Check the server and retry."))
    return api_keys[0]


def _verify_node(settings, api_key):
    # Pin the connection to the SSH target while checking the real domain’s certificate.
    # Redirects and environment proxies must never receive the new node API key.
    _check_dns(settings)
    domain = settings["domain"]
    with urllib3.HTTPSConnectionPool(
        settings["ip"], port=settings["node_port"], server_hostname=domain,
        assert_hostname=domain, cert_reqs=ssl.CERT_REQUIRED, ca_certs=requests.certs.where(),
        timeout=urllib3.Timeout(connect=4, read=5),
    ) as pool:
        for attempt in range(5):
            try:
                response = pool.request(
                    "GET", "/api/health",
                    headers={"Host": settings["base_url"].removeprefix("https://"),
                             "Authorization": f"Bearer {api_key}"},
                    retries=False, redirect=False, preload_content=False,
                )
                with response:
                    health = json.loads(response.read(65536)) if response.status == 200 else {}
                if health.get("ok") is True and any(
                    iface.get("name") == "awg0" and iface.get("is_up") is True
                    for iface in health.get("interfaces", [])
                ):
                    return
            except (urllib3.exceptions.HTTPError, OSError, ValueError, AttributeError, TypeError):
                pass
            if attempt < 4:
                time.sleep(2)
    raise SetupError("The panel could not verify the node’s HTTPS API and awg0. Check the certificate, service and inbound API port.")


def _run_job(path):
    with path.open(encoding="utf-8") as stream:
        state = json.load(stream)

    def update(status, stage, message, **fields):
        state.update(status=status, stage=stage, message=message, updated_at=time.time(), **fields)
        _write_state(path, state)

    def stage(name):
        update("running", name, STATUSES[name])

    settings = state["settings"]
    try:
        password = sys.stdin.read(1025)
        sys.stdin.close()
        if not password:
            raise SetupError("The SSH password could not be delivered. Retry with the password.")
        stage("dns")
        _check_dns(settings)
        stage("ssh")
        with _connect_ssh(settings, password, path.parent) as client:
            stage("bootstrap")
            api_key = _install(client, settings, password, stage)
        del password

        stage("health")
        _verify_node(settings, api_key)
        stage("register")
        from panel_core.node_registry import NodeAlreadyExists, register_provisioned_node
        try:
            node_id = register_provisioned_node(settings["name"], settings["base_url"], api_key)
        except NodeAlreadyExists as exc:
            raise SetupConflict(str(exc)) from None
        update("done", "done", "Node installed, verified and added to the panel.", node_id=node_id)
    except SetupError as exc:
        update("failed", state["stage"], str(exc))
    except Exception:
        label = STATUSES.get(state["stage"], "Starting the installer")
        update("failed", state["stage"], f"{label} failed. Check the server and retry.")


if __name__ == "__main__":
    _run_job(Path(sys.argv[1]))
