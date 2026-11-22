"""AmneziaWG interface settings shared by the panel and Node."""
import base64
import ipaddress
import os
import re
import secrets
import subprocess
from pathlib import Path
from tempfile import mkstemp


DEFAULT_NODE_INTERFACE = "awg0"
DEFAULT_NODE_ADDRESS = "10.64.0.1/14"
LEGACY_NODE_ADDRESS = "10.10.10.1/24"
_PRIVATE_IPV4_NETWORKS = tuple(map(ipaddress.IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


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


if __name__ == "__main__":
    _main()
