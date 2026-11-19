"""AmneziaWG interface settings shared by the panel and Node."""
import base64
import secrets
from pathlib import Path


_FIELDS = (
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
    "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
)
_FIELD_NAMES = {name.lower(): name for name in _FIELDS}


def new_interface_lines():
    """Create an AWG 3.1 profile, with a separate header key per interface."""
    header_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    return [
        "S1 = 32",
        "S2 = 48",
        "S3 = 24",
        "S4 = 16",
        f"HeaderProtectionKey = {header_key}",
    ]


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
