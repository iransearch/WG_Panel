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

import node


ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent"
STATE = ROOT / ".panel-setup"
UNIT = Path("/etc/systemd/system/wg-node-agent.service")
SERVICE = UNIT.name
INTERFACE = "awg0"
AWG_SERVICE = f"awg-quick@{INTERFACE}.service"
ADDRESS = ipaddress.IPv4Interface("10.10.10.1/24")


def stop(reason):
    print(f"WG_ERROR:{reason}", flush=True)
    raise SystemExit(1)


def step(name):
    print(f"WG_STAGE:{name}", flush=True)


def run(*argv, capture=False, timeout=300):
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="a")
    return subprocess.run(argv, stdin=subprocess.DEVNULL, check=True, env=env,
                          text=True, stdout=subprocess.PIPE if capture else None,
                          timeout=timeout).stdout


def check_port(port, *, udp=False):
    protocol = "u" if udp else "t"
    return not run("ss", f"-Hln{protocol}", f"sport = :{port}", capture=True).strip()


def active(service):
    return subprocess.run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0


def provision(domain, email, api_port, awg_port, address):
    distro = node._env(Path("/etc/os-release").read_text()).get("ID", "").strip('"')
    if os.geteuid() != 0 or distro not in {"debian", "ubuntu"} or not Path("/run/systemd/system").is_dir():
        stop("platform")

    settings = dict(domain=domain, api_port=api_port, awg_port=awg_port)
    conf = node.wg_dir() / f"{INTERFACE}.conf"
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
        if (env.exists() and previous != settings) or (
            conf.exists() and previous["awg_port"] != awg_port
        ):
            stop("settings")
    elif (UNIT.exists() or env.exists() or conf.exists() or hook.exists()
          or active(SERVICE) or Path(f"/sys/class/net/{INTERFACE}").exists()):
        stop("existing")

    step("dependencies")
    run("apt-get", "update", timeout=420)
    run("apt-get", "install", "-y", "ca-certificates", "curl", "certbot",
        "git", "python3-venv", "iproute2", "iptables", "nftables", timeout=600)
    if not active(SERVICE) and not check_port(api_port):
        stop("api_port")
    if not active(AWG_SERVICE) and not check_port(awg_port, udp=True):
        stop("awg_port")

    lineage = Path("/etc/letsencrypt/live") / domain
    cert = lineage / "fullchain.pem"
    key = lineage / "privkey.pem"
    if not (cert.is_file() and key.is_file()) and not check_port(80):
        stop("port80")

    if not node._wireguard_installed(ROOT):
        raise SystemExit(1)
    venv = AGENT / "venv"
    if not (venv / "bin/python").exists():
        run("python3", "-m", "venv", str(venv))
    run(str(venv / "bin/python"), "-m", "pip", "install", "-r",
        str(AGENT / "requirements.txt"), timeout=600)

    node._write(STATE, json.dumps(settings))
    step("interface")
    if not conf.exists():
        routes = json.loads(run("ip", "-j", "-4", "route", "show", "table", "main", capture=True))
        if any(
            route.get("dst") not in (None, "default")
            and ipaddress.IPv4Network(route["dst"], strict=False).overlaps(ADDRESS.network)
            for route in routes
        ):
            stop("network")
        private_key, _ = node.gen_keypair()
        node._write(conf, node._wg_conf(str(ADDRESS), str(awg_port), private_key, node._default_iface(), root=ROOT))
    run("systemctl", "enable", "--now", AWG_SERVICE)
    if not active(AWG_SERVICE):
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
        raise SystemExit(1)
    node._write(hook, f'#!/bin/sh\n[ "$RENEWED_LINEAGE" = {shlex.quote(str(lineage))} ] || exit 0\n'
                      f'exec systemctl try-restart {SERVICE}\n')
    hook.chmod(0o755)
    run("systemctl", "enable", "--now", "certbot.timer")
    print(f"WG_API_KEY:{api_key}", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    provision(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
