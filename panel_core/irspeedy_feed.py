"""Export a panel-generated AmneziaWG client config as wg share links."""

from base64 import b64decode
from binascii import Error as Base64Error
from ipaddress import ip_interface
from urllib.parse import quote, urlencode, urlsplit

from agent.awg_config import parameter_lines

_AWG_NAMES = {
    "HeaderProtectionKey": "header_protection_key",
    "ContentPaddingAddition": "content_padding_addition",
    "RekeyAfterTime": "rekey_after_time",
    "RekeyTimeout": "rekey_timeout",
    "RejectAfterTime": "reject_after_time",
    "KeepaliveTimeout": "keepalive_timeout",
    "MaxHandshakeAttempts": "max_handshake_attempts",
    "RandomTrailers": "random_trailers",
    "DisableCookies": "disable_cookies",
}


def _key(value):
    try:
        return len(b64decode(value, validate=True)) == 32
    except (ValueError, Base64Error):
        return False


def _authority(endpoint):
    parsed = urlsplit("wg://" + endpoint)
    port = parsed.port
    host = parsed.hostname
    if (
        not host or not port or parsed.username is not None
        or parsed.password is not None or parsed.path or parsed.query
        or parsed.fragment or any(char.isspace() for char in host)
    ):
        raise ValueError("invalid WireGuard endpoint")
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def share_uris(config, name, alternate_endpoints=()):
    sections = {}
    section = None
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in ("[Interface]", "[Peer]"):
            if line in sections:
                raise ValueError("duplicate section")
            section = sections.setdefault(line, {})
        elif section is not None and "=" in line:
            key, value = line.split("=", 1)
            section[key.strip()] = value.strip()

    iface = sections.get("[Interface]", {})
    peer = sections.get("[Peer]", {})
    private = iface.get("PrivateKey", "")
    public = peer.get("PublicKey", "")
    if not _key(private) or not _key(public):
        raise ValueError("missing WireGuard key")

    addresses = ",".join(str(ip_interface(value.strip())) for value in iface.get("Address", "").split(","))
    params = {
        "private_key": private,
        "peer_public_key": public,
        "local_address": addresses,
        "enable_amnezia": "true",
    }
    for line in parameter_lines(iface):
        key, _, value = line.partition(" = ")
        params[_AWG_NAMES.get(key, key.lower())] = value
    if len(params) == 4:
        raise ValueError("missing AmneziaWG settings")
    for values, keys in (
        (iface, {"MTU": "mtu", "DNS": "dns"}),
        (peer, {
            "AllowedIPs": "allowed_ips",
            "PresharedKey": "pre_shared_key",
            "PersistentKeepalive": "persistent_keepalive",
        }),
    ):
        for config_key, uri_key in keys.items():
            if values.get(config_key):
                params[uri_key] = values[config_key]

    # Alternate query names read by standard Exclave WireGuard imports.
    params.update(privatekey=private, publickey=public, address=addresses)
    if "pre_shared_key" in params:
        params["presharedkey"] = params["pre_shared_key"]
    query = urlencode(params, quote_via=quote)
    name = name or 'AmneziaWG'
    links = []
    for index, endpoint in enumerate((peer.get("Endpoint", ""), *alternate_endpoints)):
        authority = _authority(endpoint)
        label = name if index == 0 else f"{name} · {authority}"
        links.append(f"wg://{authority}?{query}#{quote(label, safe='')}")
    return links


def share_uri(config, name):
    return share_uris(config, name)[0]
