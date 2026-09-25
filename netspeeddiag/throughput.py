"""
Multi-stream HTTP throughput engine.

Each stream is a thread with its own ``requests.Session`` (its own TCP
connection) that keeps downloading (or uploading) from its URL until the
deadline, re-issuing the request when a body ends. A sampler records
the aggregate byte count every :data:`SAMPLE_INTERVAL` seconds, which
gives the throughput time series, the steady-state rate (after the
warm-up / slow-start window) and the peak.

Download rates come from the bytes the application received. Upload
rates come from the interface ``tx_bytes`` counter instead, because
bytes handed to the socket sit in a send buffer of several MB before
reaching the wire (on a slow uplink that would inflate the result);
the wire figure includes TCP/IP headers (~3-5%) and any concurrent
traffic.

Kernel TCP counters are diffed around the test to build a loss
*indicator* (not a loss rate): on download, segments that had to be
queued out of order per received packet (one lost packet makes every
packet behind it arrive "after a gap", so this amplifies loss events);
on upload, retransmitted segments per sent packet. On a clean line both
stay near 0.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Dict, List

import requests

from . import system_probe

SAMPLE_INTERVAL = 0.5
"""Seconds between throughput samples."""

CHUNK_BYTES = 64 * 1024
"""Read size for download bodies."""

UPLOAD_REQUEST_BYTES = 25_000_000
"""Body size of each upload request (the stream loops)."""

CONNECT_TIMEOUT = 5
"""TCP / TLS connect timeout in seconds."""

READ_TIMEOUT = 8
"""Socket read timeout in seconds (a stalled stream gives up)."""

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) NetSpeedDiag/1.0"
"""User-Agent sent with every request (some servers reject empty UAs)."""

_UPLOAD_PAYLOAD = os.urandom(1024 * 1024)
"""Incompressible buffer the upload bodies are cut from."""


class _StreamStats:
    """Per-stream counters (updated only by the owning thread)."""

    def __init__(self):
        """Initialize zeroed counters."""
        self.bytes = 0
        self.requests = 0
        self.errors: List[str] = []
        self.status_codes: Dict[str, int] = {}
        self.ttfb: List[float] = []


class _UploadBody:
    """
    File-like upload body with a known length (so ``requests`` sends a
    ``Content-Length`` instead of chunked encoding) that counts the
    bytes handed to the socket and stops at the deadline.
    """

    def __init__(self, stats: _StreamStats, deadline: float, size: int):
        """
        Args:
            stats: Stream counters to credit.
            deadline: ``time.monotonic()`` value to stop at.
            size: Declared body length.
        """
        self.len = size
        self._left = size
        self._stats = stats
        self._deadline = deadline
        self._offset = 0

    def read(self, amount: int = -1) -> bytes:
        """
        Return the next body slice.

        Args:
            amount: Requested size (``-1`` = default block).

        Returns:
            Up to ``amount`` bytes; ``b""`` at the end or past the
            deadline (the server then sees a short body, which is fine).
        """
        if self._left <= 0 or time.monotonic() >= self._deadline:
            return b""
        amount = CHUNK_BYTES if amount is None or amount < 0 else min(amount, CHUNK_BYTES)
        amount = min(amount, self._left)
        start = self._offset % len(_UPLOAD_PAYLOAD)
        chunk = _UPLOAD_PAYLOAD[start:start + amount]
        self._offset += len(chunk)
        self._left -= len(chunk)
        self._stats.bytes += len(chunk)
        return chunk


def _download_worker(url: str, stats: _StreamStats, deadline: float) -> None:
    """
    Download from ``url`` repeatedly until the deadline.

    Args:
        url: Target URL.
        stats: Counters of this stream.
        deadline: ``time.monotonic()`` value to stop at.
    """
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    while time.monotonic() < deadline:
        started = time.monotonic()
        try:
            with session.get(url, stream=True, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT)) as resp:
                stats.requests += 1
                code = str(resp.status_code)
                stats.status_codes[code] = stats.status_codes.get(code, 0) + 1
                stats.ttfb.append(time.monotonic() - started)
                if resp.status_code >= 400:
                    stats.errors.append(f"HTTP {resp.status_code}")
                    time.sleep(0.5)
                    continue
                for chunk in resp.raw.stream(CHUNK_BYTES, decode_content=False):
                    stats.bytes += len(chunk)
                    if time.monotonic() >= deadline:
                        break
        except Exception as e:
            if time.monotonic() < deadline:
                stats.errors.append(type(e).__name__)
                time.sleep(0.3)
    session.close()


def _upload_worker(url: str, stats: _StreamStats, deadline: float) -> None:
    """
    Upload to ``url`` repeatedly until the deadline.

    Args:
        url: Target URL.
        stats: Counters of this stream.
        deadline: ``time.monotonic()`` value to stop at.
    """
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    while time.monotonic() < deadline:
        started = time.monotonic()
        body = _UploadBody(stats, deadline, UPLOAD_REQUEST_BYTES)
        try:
            resp = session.post(
                url, data=body, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                headers={"Content-Type": "application/octet-stream"},
            )
            stats.requests += 1
            code = str(resp.status_code)
            stats.status_codes[code] = stats.status_codes.get(code, 0) + 1
            stats.ttfb.append(time.monotonic() - started)
            if resp.status_code >= 400:
                stats.errors.append(f"HTTP {resp.status_code}")
                time.sleep(0.5)
        except Exception as e:
            if time.monotonic() < deadline:
                stats.errors.append(type(e).__name__)
                time.sleep(0.3)
    session.close()


def measure(url: str, direction: str, streams: int, duration: float, warmup: float,
            interface: str = None) -> Dict:
    """
    Run one throughput test.

    Args:
        url: Target URL (every stream uses it).
        direction: ``"download"`` or ``"upload"``.
        streams: Parallel TCP connections.
        duration: Test length in seconds.
        warmup: Leading seconds excluded from the steady-state rate.
        interface: Default route interface (counter deltas).

    Returns:
        Dict with ``mbps`` (whole test), ``steady_mbps``, ``peak_mbps``
        (best 1 s window), ``bytes``, ``series`` (Mbps per sample),
        ``source`` (``application`` / ``interface`` counters used for
        the rates), ``app_mbps`` / ``wire_mbps`` (both views),
        ``per_stream_mbps``, ``ttfb_ms``, ``requests``,
        ``status_codes``, ``errors`` (counted by kind), ``tcp`` counter
        deltas plus ``loss_indicator_pct`` and ``iface`` deltas.
    """
    worker = _download_worker if direction == "download" else _upload_worker
    stats = [_StreamStats() for _ in range(streams)]
    tcp_before = system_probe.tcp_counters()
    if_before = system_probe.interface_counters(interface)
    start = time.monotonic()
    deadline = start + duration
    threads = [
        threading.Thread(target=worker, args=(url, s, deadline), daemon=True) for s in stats
    ]
    for t in threads:
        t.start()

    wire_key = "rx_bytes" if direction == "download" else "tx_bytes"
    wire_start = if_before.get(wire_key, 0)
    app_samples, wire_samples = [(0.0, 0)], [(0.0, 0)]
    while True:
        now = time.monotonic()
        if now >= deadline:
            break
        time.sleep(min(SAMPLE_INTERVAL, deadline - now))
        elapsed = time.monotonic() - start
        app_samples.append((elapsed, sum(s.bytes for s in stats)))
        wire = system_probe.interface_counters(interface).get(wire_key)
        wire_samples.append((elapsed, wire - wire_start if wire is not None else 0))
    tcp_after = system_probe.tcp_counters()
    if_after = system_probe.interface_counters(interface)
    for t in threads:
        t.join(timeout=2)

    primary = app_samples if direction == "download" or not interface else wire_samples
    result = summarize(primary, stats, duration, warmup, direction,
                       system_probe.counter_delta(tcp_before, tcp_after),
                       system_probe.counter_delta(if_before, if_after))
    result["source"] = "application" if primary is app_samples else "interface"
    result["app_mbps"] = _mbps(app_samples[-1][1], app_samples[-1][0])
    result["wire_mbps"] = _mbps(wire_samples[-1][1], wire_samples[-1][0]) if interface else None
    return result


def _mbps(byte_count: float, seconds: float) -> float:
    """
    Convert bytes over seconds to megabits per second.

    Args:
        byte_count: Bytes transferred.
        seconds: Elapsed seconds.

    Returns:
        Mbps rounded to 2 decimals (0 for a non-positive window).
    """
    return round(byte_count * 8 / seconds / 1e6, 2) if seconds > 0 else 0.0


def _bytes_at(samples: List, when: float) -> float:
    """
    Linearly interpolate the cumulative byte count at ``when``.

    Args:
        samples: ``(elapsed, cumulativeBytes)`` pairs, sorted.
        when: Elapsed seconds.

    Returns:
        Interpolated byte count.
    """
    for (t0, b0), (t1, b1) in zip(samples, samples[1:]):
        if t0 <= when <= t1:
            return b0 + (b1 - b0) * ((when - t0) / (t1 - t0) if t1 > t0 else 0)
    return samples[-1][1]


def summarize(samples: List, stats: List[_StreamStats], duration: float, warmup: float,
              direction: str, tcp_delta: Dict, if_delta: Dict) -> Dict:
    """
    Build the result document of a throughput test.

    Args:
        samples: ``(elapsed, cumulativeBytes)`` pairs starting at ``(0, 0)``.
        stats: Per-stream counters.
        duration: Planned test length.
        warmup: Seconds excluded from the steady-state rate.
        direction: ``"download"`` or ``"upload"``.
        tcp_delta: TCP counter deltas over the test.
        if_delta: Interface counter deltas over the test.

    Returns:
        See :func:`measure`.
    """
    elapsed = samples[-1][0] or duration
    total = samples[-1][1]
    warmup = min(warmup, elapsed / 2)
    series = [
        _mbps(b1 - b0, t1 - t0) for (t0, b0), (t1, b1) in zip(samples, samples[1:]) if t1 > t0
    ]
    peak = 0.0
    t = 0.0
    while t + 1.0 <= elapsed:
        peak = max(peak, _mbps(_bytes_at(samples, t + 1.0) - _bytes_at(samples, t), 1.0))
        t += SAMPLE_INTERVAL
    errors: Dict[str, int] = {}
    codes: Dict[str, int] = {}
    ttfb: List[float] = []
    for s in stats:
        for e in s.errors:
            errors[e] = errors.get(e, 0) + 1
        for k, v in s.status_codes.items():
            codes[k] = codes.get(k, 0) + v
        ttfb.extend(s.ttfb)

    tcp = dict(tcp_delta)
    if direction == "download":
        lost, base = tcp_delta.get("TCPOFOQueue", 0), if_delta.get("rx_packets") or tcp_delta.get("InSegs", 0)
    else:
        lost, base = tcp_delta.get("RetransSegs", 0), if_delta.get("tx_packets") or tcp_delta.get("OutSegs", 0)
    tcp["loss_indicator_pct"] = round(100.0 * lost / base, 2) if base > 1000 else None

    return {
        "mbps": _mbps(total, elapsed),
        "steady_mbps": _mbps(total - _bytes_at(samples, warmup), elapsed - warmup),
        "peak_mbps": round(peak, 2),
        "bytes": total,
        "elapsed_s": round(elapsed, 2),
        "series": series,
        "per_stream_mbps": [_mbps(s.bytes, elapsed) for s in stats],
        "ttfb_ms": round(1000 * sum(ttfb) / len(ttfb), 1) if ttfb and direction == "download" else None,
        "requests": sum(s.requests for s in stats),
        "status_codes": codes,
        "errors": errors,
        "tcp": tcp,
        "iface": if_delta,
    }
