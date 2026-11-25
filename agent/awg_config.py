"""AmneziaWG interface settings shared by the panel and Node."""
import base64
import ipaddress
import json
import os
import re
import secrets
import subprocess
from pathlib import Path
from tempfile import TemporaryFile, mkstemp


DEFAULT_NODE_INTERFACE = "awg0"
DEFAULT_NODE_ADDRESS = "10.64.0.1/14"
LEGACY_NODE_ADDRESS = "10.10.10.1/24"
_AWG_QUICK_CONF_DIR = Path("/etc/amnezia/amneziawg")
_PRIVATE_IPV4_NETWORKS = tuple(map(ipaddress.IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


def activate_created_interface(config_path, *, auto_up):
    """Register boot startup and optionally bring up a saved interface now."""
    path = Path(config_path).absolute()
    unit = f"awg-quick@{path.stem}.service"
    boot_error = None
    try:
        if path.parent.resolve() != _AWG_QUICK_CONF_DIR.resolve():
            boot_error = f"{unit} expects its configuration in {_AWG_QUICK_CONF_DIR}."
        else:
            result = subprocess.run(
                ["systemctl", "enable", unit], capture_output=True, text=True,
                errors="replace", timeout=5, check=False,
            )
            if result.returncode:
                boot_error = (result.stderr or result.stdout).strip() or f"Could not enable {unit}."
    except (OSError, subprocess.SubprocessError) as exc:
        boot_error = str(exc)

    up_error = None
    if auto_up:
        try:
            # A userspace AWG daemon can keep inherited output descriptors open.
            with TemporaryFile() as output:
                result = subprocess.run(
                    ["awg-quick", "up", str(path)], stdout=output,
                    stderr=subprocess.STDOUT, timeout=20, check=False,
                )
                if result.returncode:
                    output.seek(0)
                    up_error = output.read().decode("utf-8", "replace").strip()
                    up_error = up_error or f"awg-quick up {path.stem} failed."
        except (OSError, subprocess.SubprocessError) as exc:
            up_error = str(exc)

    return up_error, boot_error


def node_interface_settings(name, address):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", name):
        raise ValueError("Use 1–15 letters, digits, underscores, dots or dashes. Start the name with a letter or digit.")
    if not isinstance(address, str) or not re.fullmatch(r"[0-9.]+/[0-9]{1,2}", address):
        raise ValueError("Enter a private IPv4 address in CIDR format, such as 10.64.0.1/14.")
    try:
        interface = ipaddress.IPv4Interface(address)
    except ValueError:
        raise ValueError("Enter a valid private IPv4 address with a CIDR prefix.") from None
    if not any(interface.network.subnet_of(network) for network in _PRIVATE_IPV4_NETWORKS):
        raise ValueError("The entire interface subnet must be within a private IPv4 range.")
    if interface.ip in (interface.network.network_address, interface.network.broadcast_address):
        raise ValueError("Use a usable server IP within a subnet that has room for clients.")
    return name, interface


_FIELDS = (
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
    "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
)
_FIELD_NAMES = {name.lower(): name for name in _FIELDS}


_DEFAULT_PROFILE = {
    "Jc": "6",
    "Jmin": "48",
    "Jmax": "135",
    "S1": "53",
    "S2": "56",
    "S3": "52",
    "S4": "13",
    "H1": "251985833",
    "H2": "1038694419",
    "H3": "1548780894",
    "H4": "1701813191",
    "I1": "<r 164>",
    "ContentPaddingAddition": "21-34",
    "RekeyAfterTime": "100-134",
    "RekeyTimeout": "4-8",
    "RejectAfterTime": "165-229",
    "KeepaliveTimeout": "8-13",
    "MaxHandshakeAttempts": "21-32",
    "RandomTrailers": "on",
    "DisableCookies": "on",
}


def new_interface_lines(header_key=None):
    """Create the default AWG 3.1 profile with a header key for this interface."""
    if header_key is None:
        header_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    return parameter_lines({**_DEFAULT_PROFILE, "HeaderProtectionKey": header_key})


def read_parameters(path):
    """Read only protocol fields from [Interface], never private keys or hooks."""
    parameters = {}
    in_interface = False
    with Path(path).open(encoding="utf-8") as source:
        for raw in source:
            line = raw.partition("#")[0].strip()
            if line.startswith("[") and line.endswith("]"):
                in_interface = line.lower() == "[interface]"
            elif in_interface:
                name, _, value = line.partition("=")
                field = _FIELD_NAMES.get(name.strip().lower())
                if field and value.strip():
                    parameters[field] = value.strip()
    return parameters


def parameter_lines(parameters):
    """Render only known, single-line values, including those from a Node."""
    if not isinstance(parameters, dict):
        return []
    lines = []
    for name in _FIELDS:
        value = parameters.get(name)
        if isinstance(value, str) and value and not any(c in value for c in "\r\n\x00#"):
            lines.append(f"{name} = {value}")
    return lines


def with_default_profile(config):
    """Replace only AWG protocol options in the existing [Interface] block."""
    lines = config.splitlines(keepends=True)
    sections = [
        (index, header.lower())
        for index, line in enumerate(lines)
        if (header := line.partition("#")[0].strip()).startswith("[") and header.endswith("]")
    ]
    interfaces = [index for index, header in sections if header == "[interface]"]
    if len(interfaces) != 1:
        raise ValueError("Expected one [Interface] block in the config.")

    start = interfaces[0]
    end = next((index for index, _ in sections if index > start), len(lines))
    options = []
    header_key = None
    for line in lines[start + 1:end]:
        name, separator, value = line.partition("#")[0].partition("=")
        field = _FIELD_NAMES.get(name.strip().lower()) if separator else None
        if not field:
            options.append(line)
        elif field == "HeaderProtectionKey":
            candidate = value.strip()
            try:
                decoded = base64.b64decode(candidate, validate=True)
            except ValueError:
                continue
            if len(decoded) == 32 and any(decoded):
                header_key = candidate

    newline = "\r\n" if lines[start].endswith("\r\n") else "\n"
    profile = newline.join(new_interface_lines(header_key)) + newline
    return "".join([
        *lines[:start], lines[start].rstrip("\r\n"), newline, profile, *options, *lines[end:]
    ])


def _save_profile_file(path, text, suffix):
    fd, name = mkstemp(dir=path.parent, prefix=f"{path.name}{suffix}")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as target:
            target.write(text)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        Path(name).unlink()
        raise
    return Path(name)


def _apply_default_profile(path):
    interface = path.stem
    unit = f"awg-quick@{interface}.service"
    with_default_profile(path.read_bytes().decode("utf-8"))

    active = subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
    live = subprocess.run(["awg", "show", interface], capture_output=True).returncode == 0
    if active:
        subprocess.run(["systemctl", "stop", unit], check=True)
    elif live:
        subprocess.run(["awg-quick", "down", str(path)], check=True)

    backup = None
    installed = False
    try:
        # Read again after stop, since a config with SaveConfig may have changed.
        original = path.read_bytes().decode("utf-8")
        updated = with_default_profile(original)
        backup = _save_profile_file(path, original, ".bak-")
        staged = _save_profile_file(path, updated, ".stage-")
        try:
            staged.replace(path)
            installed = True
        finally:
            staged.unlink(missing_ok=True)
        subprocess.run(["systemctl", "start", unit], check=True)
        subprocess.run(["awg", "show", interface], check=True, capture_output=True)
    except BaseException:
        if installed:
            try:
                subprocess.run(["systemctl", "stop", unit], check=True)
            finally:
                backup.replace(path)
        if active or live:
            subprocess.run(["systemctl", "start", unit], check=True)
        raise
    return backup


def _main():
    import argparse

    parser = argparse.ArgumentParser(description="Apply the default AWG profile and restart the specified interfaces.")
    parser.add_argument("interface", nargs="+", help="Existing interface names, such as wg0 or wg1")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run with sudo.")
    paths = []
    for name in args.interface:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) or name in {".", ".."}:
            parser.error(f"Invalid interface name: {name}")
        path = Path("/etc/amnezia/amneziawg") / f"{name}.conf"
        if not path.is_file():
            parser.error(f"Missing config: {path}")
        paths.append(path)
    for path in dict.fromkeys(paths):
        try:
            backup = _apply_default_profile(path)
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            parser.exit(1, f"{path.stem}: {error}\n")
        print(f"{path.stem}: active with the default AWG profile. Backup: {backup}")


PEER_REMOVAL_BATCH = 4096


def config_without_peers(config, public_keys):
    """Remove only peer blocks whose public keys are in the confirmed batch."""
    def retain(block):
        if not block or block[0].partition('#')[0].strip().lower() != '[peer]':
            return True
        return not any(
            key.strip().lower() == 'publickey' and value.strip() in public_keys
            for key, _, value in (line.partition('#')[0].partition('=') for line in block[1:])
        )

    output = []
    block = []
    for line in config.splitlines(keepends=True):
        if line.lstrip().startswith('['):
            if retain(block):
                output.extend(block)
            block = []
        block.append(line)
    if retain(block):
        output.extend(block)
    return ''.join(output)


def remove_interface_peers(name, path, public_keys, write_config):
    """Remove a batch from runtime and disk, with verification before the caller deletes its records."""
    try:
        with open(path, encoding='utf-8', errors='surrogateescape', newline='') as handle:
            original = handle.read()
    except FileNotFoundError:
        original = None
    active = subprocess.check_output(
        ['awg', 'show', 'interfaces'], stderr=subprocess.PIPE, timeout=8, text=True,
    ).split()
    if name in active:
        def live_keys():
            return set(subprocess.check_output(
                ['awg', 'show', name, 'peers'], stderr=subprocess.PIPE, timeout=8, text=True,
            ).split())

        removing = sorted(public_keys & live_keys())
        for offset in range(0, len(removing), 512):
            command = ['awg', 'set', name]
            for key in removing[offset:offset + 512]:
                command.extend(('peer', key, 'remove'))
            subprocess.run(command, capture_output=True, timeout=12, check=True)
        if removing and public_keys & live_keys():
            raise RuntimeError('Some peers are still present in the AmneziaWG runtime.')

    if original is not None:
        updated = config_without_peers(original, public_keys)
        if updated != original:
            write_config(path, updated)


def remove_peer_blackholes(addresses):
    """Remove exact host blackholes left behind by disabled peers."""
    for version in (4, 6):
        hosts = {address for address in addresses if address.version == version}
        if not hosts:
            continue
        family = f'-{version}'
        output = subprocess.check_output(
            ['ip', family, '-j', 'route', 'show', 'type', 'blackhole'],
            stderr=subprocess.PIPE, timeout=8, text=True,
        )
        routes = []
        for route in json.loads(output):
            try:
                network = ipaddress.ip_network(route.get('dst', ''), strict=False)
            except ValueError:
                continue
            if network.prefixlen == network.max_prefixlen and network.network_address in hosts:
                routes.append(f'route del blackhole {network}')
        if routes:
            subprocess.run(
                ['ip', family, '-batch', '-'], input='\n'.join(routes) + '\n',
                text=True, capture_output=True, timeout=15, check=True,
            )



if __name__ == "__main__":
    _main()
