"""
Local system and connection context.

Collects everything about the measuring machine that can explain a bad
result before blaming the ISP: the default route interface (wired vs
Wi-Fi, negotiated link speed, error counters), the TCP stack tuning
(congestion control, qdisc), DNS servers, the public IP / ASN and the
first hops of the path (to detect double NAT).

Also exposes :func:`tcp_counters` / :func:`interface_counters`, the
kernel counter snapshots the throughput tests diff to estimate packet
loss and reordering.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
from typing import Dict, List, Optional

import requests

TCP_SNMP_KEYS = ("InSegs", "OutSegs", "RetransSegs", "InErrs")
"""``Tcp:`` counters read from ``/proc/net/snmp``."""

TCP_EXT_KEYS = (
    "TCPOFOQueue", "TCPLostRetransmit", "TCPDSACKOldSent",
    "TCPTimeouts", "TCPLossProbes",
)
"""``TcpExt:`` counters read from ``/proc/net/netstat``."""

INTERFACE_COUNTER_KEYS = (
    "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
    "rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
)
"""Per-interface counters read from ``/sys/class/net/<if>/statistics``."""


def _read_file(path: str) -> Optional[str]:
    """
    Read a small text file.

    Args:
        path: Absolute path.

    Returns:
        The stripped content, or ``None`` when unreadable.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return None


def default_route() -> Dict:
    """
    Parse the IPv4 default route from ``/proc/net/route``.

    Returns:
        Dict with ``interface`` and ``gateway`` (both ``None`` when no
        default route exists).
    """
    content = _read_file("/proc/net/route") or ""
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 3 or fields[1] != "00000000":
            continue
        gateway_hex = fields[2]
        gateway = socket.inet_ntoa(bytes.fromhex(gateway_hex)[::-1])
        return {"interface": fields[0], "gateway": gateway}
    return {"interface": None, "gateway": None}


def interface_info(interface: str) -> Dict:
    """
    Describe a network interface.

    Args:
        interface: Interface name (e.g. ``enp4s0``).

    Returns:
        Dict with ``name``, ``operstate``, ``speed_mbps``, ``duplex``,
        ``mtu``, ``mac``, ``wireless`` and, for Wi-Fi, the ``wifi_link``
        text reported by ``iw``.
    """
    base = f"/sys/class/net/{interface}"
    speed = _read_file(f"{base}/speed")
    info = {
        "name": interface,
        "operstate": _read_file(f"{base}/operstate"),
        "speed_mbps": int(speed) if speed and speed.lstrip("-").isdigit() else None,
        "duplex": _read_file(f"{base}/duplex"),
        "mtu": _read_file(f"{base}/mtu"),
        "mac": _read_file(f"{base}/address"),
        "wireless": os.path.isdir(f"{base}/wireless") or os.path.isdir(f"{base}/phy80211"),
        "wifi_link": None,
    }
    if info["wireless"] and shutil.which("iw"):
        info["wifi_link"] = _run(["iw", "dev", interface, "link"], timeout=5)
    return info


def interface_counters(interface: Optional[str]) -> Dict[str, int]:
    """
    Snapshot the interface statistics counters.

    Args:
        interface: Interface name; ``None`` yields an empty dict.

    Returns:
        Dict counter name -> value (see :data:`INTERFACE_COUNTER_KEYS`).
    """
    counters = {}
    if not interface:
        return counters
    for key in INTERFACE_COUNTER_KEYS:
        value = _read_file(f"/sys/class/net/{interface}/statistics/{key}")
        if value and value.isdigit():
            counters[key] = int(value)
    return counters


def _parse_proc_table(path: str, prefix: str, keys) -> Dict[str, int]:
    """
    Parse a two-line ``/proc/net/{snmp,netstat}`` table.

    Args:
        path: Proc file path.
        prefix: Row prefix (``Tcp:`` / ``TcpExt:``).
        keys: Counter names to extract.

    Returns:
        Dict counter name -> value for the keys present.
    """
    lines = [ln for ln in (_read_file(path) or "").splitlines() if ln.startswith(prefix)]
    if len(lines) < 2:
        return {}
    names, values = lines[0].split()[1:], lines[1].split()[1:]
    table = dict(zip(names, values))
    return {k: int(table[k]) for k in keys if k in table and table[k].lstrip("-").isdigit()}


def tcp_counters() -> Dict[str, int]:
    """
    Snapshot the system-wide TCP counters.

    Returns:
        Dict with the :data:`TCP_SNMP_KEYS` and :data:`TCP_EXT_KEYS`
        values. Deltas across a test estimate loss (out-of-order
        segments on download, retransmissions on upload); they are
        system wide, so concurrent traffic adds a little noise.
    """
    counters = _parse_proc_table("/proc/net/snmp", "Tcp:", TCP_SNMP_KEYS)
    counters.update(_parse_proc_table("/proc/net/netstat", "TcpExt:", TCP_EXT_KEYS))
    return counters


def counter_delta(before: Dict[str, int], after: Dict[str, int]) -> Dict[str, int]:
    """
    Compute ``after - before`` for every shared counter.

    Args:
        before: Earlier snapshot.
        after: Later snapshot.

    Returns:
        Dict counter name -> delta.
    """
    return {k: after[k] - before[k] for k in after if k in before}


def _run(cmd: List[str], timeout: int = 10) -> Optional[str]:
    """
    Run a command and capture stdout.

    Args:
        cmd: Argument vector.
        timeout: Seconds before giving up.

    Returns:
        The stripped stdout, or ``None`` on failure.
    """
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def is_private_address(address: Optional[str]) -> bool:
    """
    Tell whether an address is private / CGNAT (not publicly routable).

    Args:
        address: IP string (hostnames and ``???`` return ``False``).

    Returns:
        ``True`` for RFC1918, CGNAT (100.64/10) and link-local ranges.
    """
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return False
    return ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10")


def first_hops(target: str, max_hops: int = 5) -> List[Dict]:
    """
    Trace the first hops toward ``target`` (double NAT / CGNAT check).

    Args:
        target: Host to trace toward.
        max_hops: Maximum TTL.

    Returns:
        List of ``{"hop", "host", "private", "cgnat", "avg_ms"}`` dicts
        (empty when ``mtr`` is not installed or fails).
    """
    if not shutil.which("mtr"):
        return []
    raw = _run(["mtr", "-j", "-n", "-c", "3", "-m", str(max_hops), target], timeout=30)
    try:
        hubs = json.loads(raw)["report"]["hubs"]
    except Exception:
        return []
    return [
        {"hop": h.get("count"), "host": h.get("host"), "private": is_private_address(h.get("host")),
         "cgnat": is_cgnat_address(h.get("host")), "avg_ms": h.get("Avg")}
        for h in hubs
    ]


def is_cgnat_address(address: Optional[str]) -> bool:
    """
    Tell whether an address is in the carrier-grade NAT range.

    Args:
        address: IP string.

    Returns:
        ``True`` for 100.64.0.0/10 (RFC 6598, used by ISPs for CGNAT).
    """
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network("100.64.0.0/10")
    except (ValueError, TypeError):
        return False


def public_ip_info(url: str) -> Dict:
    """
    Resolve the public IP, ISP / ASN and location.

    Args:
        url: ipinfo-compatible JSON endpoint.

    Returns:
        The parsed document (``{"error": ...}`` on failure).
    """
    try:
        resp = requests.get(url, timeout=8)
        data = resp.json()
        return {k: data.get(k) for k in ("ip", "hostname", "city", "region", "country", "org")}
    except Exception as e:
        return {"error": str(e)}


def collect(public_ip_url: str, first_hops_target: str) -> Dict:
    """
    Collect the full system context of a run.

    Args:
        public_ip_url: Endpoint used by :func:`public_ip_info`.
        first_hops_target: Host used by :func:`first_hops`.

    Returns:
        Dict with ``hostname``, ``kernel``, ``route``, ``interface``,
        ``tcp`` (stack tuning), ``dns``, ``public`` and ``first_hops``.
    """
    route = default_route()
    dns = [
        ln.split()[1] for ln in (_read_file("/etc/resolv.conf") or "").splitlines()
        if ln.startswith("nameserver") and len(ln.split()) > 1
    ]
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "route": route,
        "interface": interface_info(route["interface"]) if route["interface"] else None,
        "tcp": {
            "congestion_control": _read_file("/proc/sys/net/ipv4/tcp_congestion_control"),
            "available_congestion_control": _read_file("/proc/sys/net/ipv4/tcp_available_congestion_control"),
            "default_qdisc": _read_file("/proc/sys/net/core/default_qdisc"),
            "rmem": _read_file("/proc/sys/net/ipv4/tcp_rmem"),
            "wmem": _read_file("/proc/sys/net/ipv4/tcp_wmem"),
        },
        "dns": dns,
        "public": public_ip_info(public_ip_url),
        "first_hops": first_hops(first_hops_target),
    }
