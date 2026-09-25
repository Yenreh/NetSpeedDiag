"""
Protocol-level service checks.

Optional checks configured in the ``services`` section of the test
catalog. They answer "does the stuff I actually use work well?" rather
than "how fast is the line":

* ``tcp``   repeated TCP handshakes to ``host:port`` (latency and failure
            rate; works where ICMP is filtered).
* ``https`` TCP + TLS handshake + time to first byte of a request.
* ``ssh``   SSH banner time (no login). With ``auth: true`` it also runs a
            non-interactive login using the user's own SSH config / keys
            (``BatchMode``, never prompts), and with ``throughput_mb`` it
            streams that many MB down and up through the session.
* ``dns``   UDP DNS query time and failures per resolver (queries built
            here, no ``dig`` needed).

Every check returns a result dict; failures are data, never exceptions.
"""

from __future__ import annotations

import os
import random
import socket
import ssl
import struct
import subprocess
import time
from typing import Dict, List, Optional

from .latency_probe import summarize_rtts

DEFAULT_TIMEOUT = 5.0
"""Seconds before a connect / handshake / query attempt counts as failed."""

SSH_BASE_OPTIONS = [
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "Compression=no",
    "-o", "ServerAliveInterval=5", "-o", "LogLevel=ERROR",
]
"""Options for every ``ssh`` invocation: never prompt, fail fast."""


def _resolve(host: str, port: int) -> tuple:
    """
    Resolve a host once (so DNS time is not part of the connect time).

    Args:
        host: Host name or IP.
        port: TCP port.

    Returns:
        Tuple ``(sockaddr, family, resolve_ms)``.

    Raises:
        OSError: When resolution fails.
    """
    started = time.perf_counter()
    info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
    return info[4], info[0], (time.perf_counter() - started) * 1000


def _connect(sockaddr, family, timeout: float) -> tuple:
    """
    Open a TCP connection and time the handshake.

    Args:
        sockaddr: Resolved address.
        family: Address family.
        timeout: Seconds.

    Returns:
        Tuple ``(socket, connect_ms)``.
    """
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    sock.connect(sockaddr)
    return sock, (time.perf_counter() - started) * 1000


def _attempts(count: int, interval: float, attempt) -> Dict:
    """
    Run an attempt function repeatedly and collect timings.

    Args:
        count: Attempts.
        interval: Seconds between attempts.
        attempt: Callable returning a dict of ``name -> ms`` (plus
            optional ``info``) or raising on failure.

    Returns:
        Dict with ``attempts``, ``ok``, ``fail_pct``, ``errors`` (by
        kind), one :func:`summarize_rtts` block per timing name and the
        last ``info`` value.
    """
    timings: Dict[str, List[float]] = {}
    errors: Dict[str, int] = {}
    ok, info = 0, None
    for i in range(count):
        try:
            result = attempt()
            info = result.pop("info", info)
            for key, value in result.items():
                timings.setdefault(key, []).append(value)
            ok += 1
        except Exception as e:
            kind = type(e).__name__ if not isinstance(e, OSError) or not e.strerror else e.strerror
            errors[kind] = errors.get(kind, 0) + 1
        if i < count - 1:
            time.sleep(interval)
    out = {
        "attempts": count, "ok": ok,
        "fail_pct": round(100.0 * (count - ok) / count, 1) if count else None,
        "errors": errors, "info": info,
    }
    for key, values in timings.items():
        stats = summarize_rtts(values, len(values))
        out[key] = {k: stats[k] for k in ("min", "avg", "median", "p95", "max", "jitter")}
    return out


def check_tcp(host: str, port: int, count: int = 5, interval: float = 0.3,
              timeout: float = DEFAULT_TIMEOUT) -> Dict:
    """
    Repeated TCP handshakes.

    Args:
        host: Target host.
        port: Target port.
        count: Handshakes.
        interval: Seconds between handshakes.
        timeout: Seconds per handshake.

    Returns:
        :func:`_attempts` dict with ``connect_ms`` and ``resolve_ms``.
    """
    def attempt():
        sockaddr, family, resolve_ms = _resolve(host, port)
        sock, connect_ms = _connect(sockaddr, family, timeout)
        sock.close()
        return {"connect_ms": connect_ms, "resolve_ms": resolve_ms}
    return _attempts(count, interval, attempt)


def check_https(host: str, port: int = 443, path: str = "/", count: int = 5, interval: float = 0.3,
                timeout: float = DEFAULT_TIMEOUT) -> Dict:
    """
    Repeated HTTPS requests timed per phase.

    Args:
        host: Target host (also the SNI / Host header).
        port: TCP port.
        path: Request path.
        count: Requests.
        interval: Seconds between requests.
        timeout: Seconds per phase.

    Returns:
        :func:`_attempts` dict with ``connect_ms``, ``tls_ms`` and
        ``ttfb_ms`` (request sent to first response byte); ``info`` is
        the HTTP status line.
    """
    context = ssl.create_default_context()

    def attempt():
        sockaddr, family, _ = _resolve(host, port)
        raw, connect_ms = _connect(sockaddr, family, timeout)
        started = time.perf_counter()
        sock = context.wrap_socket(raw, server_hostname=host)
        tls_ms = (time.perf_counter() - started) * 1000
        try:
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetSpeedDiag\r\nConnection: close\r\n\r\n"
            started = time.perf_counter()
            sock.sendall(request.encode())
            first = sock.recv(256)
            ttfb_ms = (time.perf_counter() - started) * 1000
        finally:
            sock.close()
        status = first.split(b"\r\n", 1)[0].decode(errors="replace")
        return {"connect_ms": connect_ms, "tls_ms": tls_ms, "ttfb_ms": ttfb_ms, "info": status}
    return _attempts(count, interval, attempt)


def check_ssh_banner(host: str, port: int = 22, count: int = 3, interval: float = 0.3,
                     timeout: float = DEFAULT_TIMEOUT) -> Dict:
    """
    Repeated SSH handshakes up to the server banner (no login).

    Args:
        host: Target host.
        port: SSH port.
        count: Attempts.
        interval: Seconds between attempts.
        timeout: Seconds per attempt.

    Returns:
        :func:`_attempts` dict with ``connect_ms`` and ``banner_ms``
        (connect to banner received); ``info`` is the banner.
    """
    def attempt():
        sockaddr, family, _ = _resolve(host, port)
        sock, connect_ms = _connect(sockaddr, family, timeout)
        try:
            started = time.perf_counter()
            banner = b""
            while b"\n" not in banner and len(banner) < 512:
                chunk = sock.recv(256)
                if not chunk:
                    break
                banner += chunk
            banner_ms = (time.perf_counter() - started) * 1000
        finally:
            sock.close()
        if not banner.startswith(b"SSH-"):
            raise ConnectionError("no SSH banner")
        return {"connect_ms": connect_ms, "banner_ms": banner_ms,
                "info": banner.split(b"\n", 1)[0].decode(errors="replace").strip()}
    return _attempts(count, interval, attempt)


def _ssh_command(check: Dict) -> List[str]:
    """
    Build the ``ssh`` argument vector of a check.

    Args:
        check: SSH check spec (``host``, optional ``user``, ``port``,
            ``identity_file``, ``options``).

    Returns:
        Argument vector without the remote command.
    """
    cmd = ["ssh", *SSH_BASE_OPTIONS]
    if check.get("port"):
        cmd += ["-p", str(check["port"])]
    if check.get("identity_file"):
        cmd += ["-i", os.path.expanduser(check["identity_file"])]
    for opt in check.get("options") or []:
        cmd += ["-o", opt]
    target = f"{check['user']}@{check['host']}" if check.get("user") else check["host"]
    return cmd + [target]


def ssh_session(check: Dict) -> Dict:
    """
    Login, and optionally measure throughput, through the user's SSH.

    Args:
        check: SSH check spec; ``throughput_mb`` > 0 enables the transfer
            test (download: remote ``head -c`` from ``/dev/zero``; upload:
            local zeros into remote ``cat > /dev/null``).

    Returns:
        Dict with ``auth_ms`` (full login + trivial command), and when
        requested ``download_mbps`` / ``upload_mbps`` (single TCP flow,
        includes SSH encryption); ``error`` on failure.
    """
    base = _ssh_command(check)
    out: Dict = {}
    started = time.perf_counter()
    try:
        proc = subprocess.run(base + ["true"], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"error": "login timed out"}
    if proc.returncode != 0:
        return {"error": (proc.stderr.strip().splitlines() or ["login failed"])[-1][:200]}
    out["auth_ms"] = round((time.perf_counter() - started) * 1000, 1)

    size = int(float(check.get("throughput_mb") or 0) * 1_000_000)
    if size <= 0:
        return out
    timeout = float(check.get("throughput_timeout_seconds", 60))
    out["download_mbps"] = _ssh_transfer(base + [f"head -c {size} /dev/zero"], size, timeout, upload=False)
    out["upload_mbps"] = _ssh_transfer(base + ["cat > /dev/null"], size, timeout, upload=True)
    return out


def _ssh_transfer(cmd: List[str], size: int, timeout: float, upload: bool) -> Optional[float]:
    """
    Stream ``size`` bytes through an SSH session and time it.

    Args:
        cmd: Full ``ssh`` argument vector including the remote command.
        size: Bytes to move.
        timeout: Seconds before giving up.
        upload: ``True`` to send, ``False`` to receive.

    Returns:
        Mbps measured from the first byte to the end, or ``None`` when
        the transfer failed or timed out.
    """
    chunk = b"\0" * 65536
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if upload else subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL if upload else subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    deadline = time.perf_counter() + timeout
    moved, first = 0, None
    try:
        while moved < size and time.perf_counter() < deadline:
            if upload:
                n = min(len(chunk), size - moved)
                proc.stdin.write(chunk[:n])
            else:
                data = proc.stdout.read1(65536)
                if not data:
                    break
                n = len(data)
            first = first or time.perf_counter()
            moved += n
        if upload:
            proc.stdin.close()
        proc.wait(timeout=max(1.0, deadline - time.perf_counter()))
    except Exception:
        proc.kill()
        return None
    if moved < size or proc.returncode != 0 or first is None:
        return None
    elapsed = time.perf_counter() - first
    return round(moved * 8 / elapsed / 1e6, 2) if elapsed > 0 else None


def _dns_packet(name: str, query_id: int) -> bytes:
    """
    Build a DNS A query.

    Args:
        name: Domain to resolve.
        query_id: 16-bit transaction id.

    Returns:
        The wire-format query.
    """
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\0"
    return header + qname + struct.pack(">HH", 1, 1)


def dns_query(server: str, name: str, timeout: float = 2.0) -> float:
    """
    Send one UDP DNS query and time the answer.

    Args:
        server: Resolver IP.
        name: Domain to resolve.
        timeout: Seconds.

    Returns:
        Milliseconds until a valid answer arrived.

    Raises:
        OSError: On timeout / network error.
        LookupError: When the resolver answers with an error code.
    """
    query_id = random.randint(0, 0xFFFF)
    packet = _dns_packet(name, query_id)
    with socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        started = time.perf_counter()
        sock.sendto(packet, (server, 53))
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == query_id:
                break
        elapsed = (time.perf_counter() - started) * 1000
    rcode = data[3] & 0x0F
    if rcode:
        raise LookupError(f"rcode {rcode}")
    return elapsed


def check_dns(servers: List[Dict], names: List[str], count: int = 3, interval: float = 0.1,
              timeout: float = 2.0) -> Dict:
    """
    Time DNS resolution per resolver.

    Args:
        servers: ``[{"name", "address"}]`` resolvers.
        names: Domains queried (each ``count`` times).
        count: Queries per name.
        interval: Seconds between queries.
        timeout: Seconds per query.

    Returns:
        Dict with ``resolvers``: one entry per server with the
        :func:`_attempts` statistics (``query_ms``).
    """
    resolvers = []
    for server in servers:
        queue = [n for n in names for _ in range(count)]

        def attempt(address=server["address"]):
            return {"query_ms": dns_query(address, queue.pop(0), timeout)}
        stats = _attempts(len(queue), interval, attempt)
        resolvers.append({"name": server.get("name") or server["address"], "address": server["address"], **stats})
    return {"resolvers": resolvers}
