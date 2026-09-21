"""Pure helpers for parsing and generating (Amnezia)WireGuard configuration.

Nothing here touches Docker, the database or the network - everything is a pure
function over strings, which makes it straightforward to unit-test.

AmneziaWG adds obfuscation parameters to the standard WireGuard ``[Interface]``
section (``Jc Jmin Jmax S1 S2 H1 H2 H3 H4`` and sometimes ``I1..I5``/``MTU``).
Clients must echo the same values, so we copy them verbatim from the server
config into every generated client config.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .errors import NoAddressAvailableError

# Obfuscation / tuning keys that must be mirrored server -> client.
AWG_INTERFACE_KEYS: tuple[str, ...] = (
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
    "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5",
    "MTU",
)


@dataclass
class Peer:
    public_key: str
    allowed_ips: str
    preshared_key: str | None = None
    endpoint: str | None = None
    comment: str | None = None


@dataclass
class WgConfig:
    """Parsed view of a wg-quick style config file."""

    interface: dict[str, str] = field(default_factory=dict)
    interface_raw: str = ""  # the ``[Interface]`` block verbatim, incl. header
    peers: list[Peer] = field(default_factory=list)

    def awg_params(self) -> dict[str, str]:
        """The obfuscation/tuning parameters present in ``[Interface]``, ordered."""
        return {k: self.interface[k] for k in AWG_INTERFACE_KEYS if k in self.interface}


def parse_config(text: str) -> WgConfig:
    """Parse a wg-quick config into a :class:`WgConfig`.

    Tolerant of blank lines, ``#``/``;`` comments and ``Key = Value`` spacing.
    """
    cfg = WgConfig()
    section: str | None = None
    current_peer: Peer | None = None
    interface_lines: list[str] = []
    pending_comment: str | None = None

    for line in text.splitlines():
        stripped = line.strip()

        if stripped.startswith(("#", ";")):
            pending_comment = stripped.lstrip("#; ").strip() or pending_comment
            if section == "interface":
                interface_lines.append(line)
            continue
        if not stripped:
            if section == "interface":
                interface_lines.append(line)
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            if section == "interface":
                interface_lines.append(line)
            elif section == "peer":
                current_peer = Peer(public_key="", allowed_ips="", comment=pending_comment)
                cfg.peers.append(current_peer)
                pending_comment = None
            continue

        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key, value = key.strip(), value.strip()

        if section == "interface":
            interface_lines.append(line)
            cfg.interface[key] = value
        elif section == "peer" and current_peer is not None:
            low = key.lower()
            if low == "publickey":
                current_peer.public_key = value
            elif low == "presharedkey":
                current_peer.preshared_key = value
            elif low == "allowedips":
                current_peer.allowed_ips = value
            elif low == "endpoint":
                current_peer.endpoint = value

    cfg.interface_raw = "\n".join(interface_lines).strip("\n")
    return cfg


def render_peer(peer: Peer) -> str:
    """Render one ``[Peer]`` block (server-side view)."""
    lines: list[str] = []
    if peer.comment:
        lines.append(f"# {peer.comment}")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {peer.public_key}")
    if peer.preshared_key:
        lines.append(f"PresharedKey = {peer.preshared_key}")
    lines.append(f"AllowedIPs = {peer.allowed_ips}")
    if peer.endpoint:
        lines.append(f"Endpoint = {peer.endpoint}")
    return "\n".join(lines)


def build_server_config(interface_raw: str, peers: list[Peer]) -> str:
    """Reassemble the server ``wg0.conf`` from a verbatim interface block + peers."""
    blocks = [interface_raw.strip("\n")]
    blocks.extend(render_peer(p) for p in peers)
    return "\n\n".join(blocks) + "\n"


def build_client_config(
    *,
    private_key: str,
    address: str,
    dns: str,
    awg_params: dict[str, str],
    server_public_key: str,
    preshared_key: str,
    endpoint: str,
    allowed_ips: str = "0.0.0.0/0, ::/0",
    persistent_keepalive: int = 25,
) -> str:
    """Produce a ready-to-import AmneziaWG/WireGuard client config."""
    lines = ["[Interface]", f"PrivateKey = {private_key}", f"Address = {address}"]
    if dns:
        lines.append(f"DNS = {dns}")
    for key, value in awg_params.items():
        lines.append(f"{key} = {value}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key}")
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.append(f"AllowedIPs = {allowed_ips}")
    lines.append(f"Endpoint = {endpoint}")
    if persistent_keepalive:
        lines.append(f"PersistentKeepalive = {persistent_keepalive}")
    return "\n".join(lines) + "\n"


def interface_network(interface: dict[str, str]) -> ipaddress.IPv4Network:
    """The IPv4 tunnel network derived from the server ``Address`` field."""
    raw = interface.get("Address", "")
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            iface = ipaddress.ip_interface(part)
        except ValueError:
            continue
        if isinstance(iface.network, ipaddress.IPv4Network):
            return ipaddress.ip_network(f"{iface.network.network_address}/{iface.network.prefixlen}")
    raise ValueError(f"could not determine IPv4 network from Address={raw!r}")


def server_tunnel_ip(interface: dict[str, str]) -> ipaddress.IPv4Address:
    raw = interface.get("Address", "")
    for part in raw.split(","):
        part = part.strip()
        try:
            iface = ipaddress.ip_interface(part)
        except ValueError:
            continue
        if isinstance(iface.ip, ipaddress.IPv4Address):
            return iface.ip
    raise ValueError(f"could not determine server tunnel IP from Address={raw!r}")


def allocate_address(
    interface: dict[str, str],
    used: set[str],
    *,
    reserve: set[str] | None = None,
) -> str:
    """Pick the lowest free ``<ip>/32`` in the tunnel subnet.

    Args:
        interface: Parsed server ``[Interface]`` dict (needs ``Address``).
        used: Addresses already assigned, as ``"10.8.1.5/32"`` or ``"10.8.1.5"``.
        reserve: Extra host IPs to treat as unavailable (defaults to the server IP).

    Raises:
        NoAddressAvailableError: The subnet is exhausted.
    """
    network = interface_network(interface)
    server_ip = server_tunnel_ip(interface)

    taken = {_host_only(a) for a in used}
    taken.add(str(server_ip))
    if reserve:
        taken.update(_host_only(a) for a in reserve)

    for host in network.hosts():
        if str(host) not in taken:
            return f"{host}/32"
    raise NoAddressAvailableError(
        f"tunnel subnet {network} is exhausted ({len(taken)} addresses in use)"
    )


def parse_listen_port(interface: dict[str, str]) -> int | None:
    value = interface.get("ListenPort")
    if value and value.isdigit():
        return int(value)
    return None


def _host_only(addr: str) -> str:
    return addr.split("/", 1)[0].strip()
