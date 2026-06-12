"""Parse Volatility 3 windows.netscan output into structured network connection dicts."""
from __future__ import annotations
import re

# Ports associated with known C2 protocols or exfiltration
SUSPICIOUS_PORTS = {
    4444, 4445, 1337, 31337, 8080, 8443, 9001, 9050,  # common C2/RAT/Tor
    6666, 6667, 6668, 6669,  # IRC (legacy botnets)
}

# Standard outbound egress ports. A *plain* established connection to an external
# IP on one of these is ordinary traffic (web/DNS/NTP) and on its own is NOT an
# IOC — flagging every external :443 connection buries real hostile IPs in CDN
# noise (Microsoft / Apple / Google). Such connections are recorded as
# informational notes and still surfaced via get_external_ips() for reputation
# lookup, but they do not set suspicious=True by themselves.
COMMON_OUTBOUND_PORTS = {80, 443, 53, 123}

# Private / loopback ranges (used for filtering)
_LOOPBACK = re.compile(r"^127\.")
_PRIVATE = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")


def parse_netscan(raw_output: str) -> list[dict]:
    """
    Parse `vol -f image windows.netscan` output.

    Volatility 3 netscan columns (tab/space separated):
        Offset  Proto  LocalAddr  LocalPort  ForeignAddr  ForeignPort  State  PID  Owner  Created
    """
    connections: list[dict] = []
    header_found = False

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith("Volatility") or line.startswith("Progress"):
            continue

        if "Proto" in line and ("LocalAddr" in line or "LocalPort" in line):
            header_found = True
            continue

        if not header_found:
            continue

        parts = line.split()
        if len(parts) < 8:
            continue

        try:
            conn = {
                "offset": parts[0],
                "proto": parts[1],
                "local_addr": parts[2],
                "local_port": _safe_int(parts[3]),
                "foreign_addr": parts[4],
                "foreign_port": _safe_int(parts[5]),
                "state": parts[6],
                "pid": _safe_int(parts[7]),
                "owner": parts[8] if len(parts) > 8 else "unknown",
                "created": " ".join(parts[9:11]) if len(parts) > 10 else "unknown",
                "suspicious": False,
                "ioc_flags": [],
                "notes": [],
            }
            _flag_connection(conn)
            connections.append(conn)
        except (ValueError, IndexError):
            continue

    return connections


def _flag_connection(conn: dict) -> None:
    flags: list[str] = []
    notes: list[str] = []

    foreign = conn["foreign_addr"]
    foreign_port = conn["foreign_port"]
    state = conn["state"]

    is_external = (
        state == "ESTABLISHED"
        and foreign
        and foreign not in ("0.0.0.0", "*", "N/A")
        and not _LOOPBACK.match(foreign)
        and not _PRIVATE.match(foreign)
    )

    # Established external connection. Egress on a standard web/DNS/NTP port is
    # ordinary traffic (informational); egress on any other port is notable and
    # worth flagging (e.g. external RDP 3389 -> T1021.001, or a custom C2 port).
    if is_external:
        if isinstance(foreign_port, int) and foreign_port not in COMMON_OUTBOUND_PORTS:
            flags.append(
                f"External connection to {foreign}:{foreign_port} on non-standard port"
            )
        else:
            notes.append(f"External connection to {foreign}:{foreign_port} (standard egress)")

    # Known suspicious ports
    if foreign_port in SUSPICIOUS_PORTS:
        flags.append(f"Suspicious remote port: {foreign_port}")
    if isinstance(conn["local_port"], int) and conn["local_port"] in SUSPICIOUS_PORTS:
        flags.append(f"Suspicious local port: {conn['local_port']}")

    # Tor exit port
    if foreign_port == 9050 or foreign_port == 9001:
        flags.append("Possible Tor traffic")

    conn["ioc_flags"] = flags
    conn["notes"] = notes
    conn["suspicious"] = len(flags) > 0


def _safe_int(s: str) -> int | str:
    try:
        return int(s)
    except ValueError:
        return s


def get_external_ips(connections: list[dict]) -> list[str]:
    """Return unique external IPs from established connections (for threat intel lookup)."""
    ips: set[str] = set()
    for c in connections:
        fa = c.get("foreign_addr", "")
        if (
            c.get("state") == "ESTABLISHED"
            and fa
            and fa not in ("0.0.0.0", "*", "N/A")
            and not _LOOPBACK.match(fa)
            and not _PRIVATE.match(fa)
        ):
            ips.add(fa)
    return sorted(ips)
