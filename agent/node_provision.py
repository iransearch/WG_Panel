#!/usr/bin/env python3
"""Noninteractive installer for nodes provisioned by WG Panel."""
import ipaddress
import json
import os
import secrets
import shlex
import subprocess
import sys
from pathlib import Path

if __package__:
    from . import node
    from .awg_config import DEFAULT_NODE_INTERFACE, LEGACY_NODE_ADDRESS, node_interface_settings
else:
    import node
    from awg_config import DEFAULT_NODE_INTERFACE, LEGACY_NODE_ADDRESS, node_interface_settings


ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent"
STATE = ROOT / ".panel-setup"
UNIT = Path("/etc/systemd/system/wg-node-agent.service")
SERVICE = UNIT.name


def stop(reason):
    print(f"WG_ERROR:{reason}", flush=True)
    raise SystemExit(1)


def step(name):
    print(f"WG_STAGE:{name}", flush=True)


def command_step(label):
    print(f"WG_STEP:{label}", flush=True)


def unit_errors(unit):
    try:
        subprocess.run(
            ["journalctl", "-u", unit, "-n", "16", "--no-pager", "-o", "cat"],
            stdin=subprocess.DEVNULL, check=False, timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def run(*argv, capture=False, timeout=300):
    command_step(shlex.join(argv))
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="a")
    try:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, check=True, env=env,
                              text=True, stdout=subprocess.PIPE if capture else None,
                              timeout=timeout).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        if argv[0] == "systemctl" and (
            argv[-1] in {SERVICE, "certbot.timer"} or argv[-1].startswith("awg-quick@")
        ):
            unit_errors(argv[-1])
        raise


def check_port(port, *, udp=False):
    protocol = "u" if udp else "t"
    return not run("ss", f"-Hln{protocol}", f"sport = :{port}", capture=True).strip()


def active(service):
    return subprocess.run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0


def provision(domain, email, api_port, awg_port, address,
              interface_name=DEFAULT_NODE_INTERFACE, interface_address=LEGACY_NODE_ADDRESS):
    interface_name, interface_address = node_interface_settings(interface_name, interface_address)
    awg_service = f"awg-quick@{interface_name}.service"
    distro = node._env(Path("/etc/os-release").read_text()).get("ID", "").strip('"')
    if os.geteuid() != 0 or distro not in {"debian", "ubuntu"} or not Path("/run/systemd/system").is_dir():
        stop("platform")

    settings = dict(domain=domain, api_port=api_port, awg_port=awg_port,
                    interface_name=interface_name, interface_address=str(interface_address))
    conf = node.wg_dir() / f"{interface_name}.conf"
    env = AGENT / ".env"
    hook = Path("/etc/letsencrypt/renewal-hooks/deploy/wg-node-agent")
    panel = subprocess.run(
        ["systemctl", "cat", "wg-panel.service"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=False,
    )
    if panel.returncode == 0:
        stop("panel")
    if STATE.exists():
        previous = json.loads(STATE.read_text())
        previous.setdefault("interface_name", DEFAULT_NODE_INTERFACE)
        previous.setdefault("interface_address", LEGACY_NODE_ADDRESS)
        previous_conf = conf.with_name(f'{previous["interface_name"]}.conf')
        config_fields = ("interface_name", "interface_address", "awg_port")
        if (env.exists() and previous != settings) or (
            previous_conf.exists() and any(previous[key] != settings[key] for key in config_fields)
        ):
            stop("settings")
        if previous_conf != conf and (conf.exists() or Path(f"/sys/class/net/{interface_name}").exists()):
            stop("existing")
    elif (UNIT.exists() or env.exists() or conf.exists() or hook.exists()
          or active(SERVICE) or Path(f"/sys/class/net/{interface_name}").exists()):
        stop("existing")

    step("dependencies")
    run("apt-get", "update", timeout=420)
    run("apt-get", "install", "-y", "ca-certificates", "curl", "certbot",
        "git", "python3-venv", "iproute2", "iptables", "nftables", timeout=600)
    if not active(SERVICE) and not check_port(api_port):
        stop("api_port")
    if not active(awg_service) and not check_port(awg_port, udp=True):
        stop("awg_port")

    lineage = Path("/etc/letsencrypt/live") / domain
    cert = lineage / "fullchain.pem"
    key = lineage / "privkey.pem"
    if not (cert.is_file() and key.is_file()) and not check_port(80):
        stop("port80")

    command_step("Install AmneziaWG tools and runtime")
    if not node._wireguard_installed(ROOT):
        raise SystemExit(1)
    venv = AGENT / "venv"
    if not (venv / "bin/python").exists():
        run("python3", "-m", "venv", str(venv))
    run(str(venv / "bin/python"), "-m", "pip", "install", "-r",
        str(AGENT / "requirements.txt"), timeout=600)

    command_step("Save node setup settings")
    node._write(STATE, json.dumps(settings))
    step("interface")
    if not conf.exists():
        routes = json.loads(run("ip", "-j", "-4", "route", "show", "table", "main", capture=True))
        if any(
            route.get("dst") not in (None, "default")
            and ipaddress.IPv4Network(route["dst"], strict=False).overlaps(interface_address.network)
            for route in routes
        ):
            stop("network")
        private_key, _ = node.gen_keypair()
        command_step(f"Write {interface_name}.conf")
        node._write(conf, node._wg_conf(str(interface_address), str(awg_port), private_key, node._default_iface(), root=ROOT))
    run("systemctl", "enable", "--now", awg_service)
    if not active(awg_service):
        unit_errors(awg_service)
        raise SystemExit(1)

    step("certificate")
    if not (cert.is_file() and key.is_file()):
        try:
            run("certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
                "--email", email, "--cert-name", domain, "-d", domain, timeout=420)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            stop("certificate")
    if not (cert.is_file() and key.is_file()):
        stop("certificate")

    step("service")
    command_step("Write node agent configuration and systemd unit")
    old_env = node._env(env.read_text()) if env.exists() else {}
    api_key = old_env.get("API_KEY") or secrets.token_urlsafe(18)
    bind = "[::]" if ipaddress.ip_address(address).version == 6 else "0.0.0.0"
    node._write(env, node.make_env({
        "API_KEY": api_key,
        "AMNEZIAWG_CONF_PATH": str(node.wg_dir()),
        "BIND": f"{bind}:{api_port}",
        "AGENT_SSL_CERT": str(cert),
        "AGENT_SSL_KEY": str(key),
    }))
    node._write(UNIT, node._agent_unit_text(ROOT))
    run("systemctl", "daemon-reload")
    if active(SERVICE):
        run("systemctl", "restart", SERVICE)
    run("systemctl", "enable", "--now", SERVICE)
    if not active(SERVICE):
        unit_errors(SERVICE)
        raise SystemExit(1)
    command_step("Install certificate renewal hook")
    node._write(hook, f'#!/bin/sh\n[ "$RENEWED_LINEAGE" = {shlex.quote(str(lineage))} ] || exit 0\n'
                      f'exec systemctl try-restart {SERVICE}\n')
    hook.chmod(0o755)
    run("systemctl", "enable", "--now", "certbot.timer")
    print(f"WG_API_KEY:{api_key}", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    provision(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], *sys.argv[6:])
