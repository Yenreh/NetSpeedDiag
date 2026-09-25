"""
Latency, packet loss and route probes.

Thin wrappers over the system ``ping`` and ``mtr`` binaries (no raw
sockets, so no root needed). :class:`PingSession` runs in the
background so it can measure latency *while* a throughput test loads
the line (bufferbloat / loss-under-load check).
"""

from __future__ import annotations

import json
import re
import shutil
import signal
import statistics
import subprocess
import threading
from typing import Dict, List, Optional

PING_RTT_RE = re.compile(r"icmp_seq=(\d+).*time=([\d.]+)\s*ms")
"""Matches one reply line of iputils ``ping``."""

PING_SENT_RE = re.compile(r"(\d+) packets transmitted")
"""Matches the transmitted-packets summary of iputils ``ping``."""


def summarize_rtts(rtts: List[float], sent: int) -> Dict:
    """
    Build latency statistics from raw round-trip times.

    Args:
        rtts: Reply RTTs in milliseconds, in arrival order.
        sent: Probes transmitted.

    Returns:
        Dict with ``sent``, ``received``, ``loss_pct``, ``min``,
        ``avg``, ``median``, ``p95``, ``max`` and ``jitter`` (mean
        absolute difference of consecutive RTTs), all in ms. Latency
        fields are ``None`` when nothing came back.
    """
    received = len(rtts)
    out = {
        "sent": sent,
        "received": received,
        "loss_pct": round(100.0 * (sent - received) / sent, 2) if sent else None,
        "min": None, "avg": None, "median": None, "p95": None, "max": None, "jitter": None,
    }
    if not rtts:
        return out
    ordered = sorted(rtts)
    out.update({
        "min": round(ordered[0], 2),
        "avg": round(statistics.fmean(rtts), 2),
        "median": round(statistics.median(rtts), 2),
        "p95": round(ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))], 2),
        "max": round(ordered[-1], 2),
        "jitter": round(
            statistics.fmean(abs(a - b) for a, b in zip(rtts, rtts[1:])), 2
        ) if len(rtts) > 1 else 0.0,
    })
    return out


def parse_ping_output(text: str, expected: int) -> Dict:
    """
    Parse iputils ``ping`` output into statistics.

    Args:
        text: Full stdout.
        expected: Probe count requested (fallback for ``sent``).

    Returns:
        The :func:`summarize_rtts` dict.
    """
    rtts = [float(m.group(2)) for m in PING_RTT_RE.finditer(text)]
    sent_match = PING_SENT_RE.search(text)
    sent = int(sent_match.group(1)) if sent_match else expected
    return summarize_rtts(rtts, sent)


def _ping_command(host: str, count: int, interval: float) -> List[str]:
    """
    Build the ``ping`` argument vector.

    Args:
        host: Target host or IP.
        count: Probes to send.
        interval: Seconds between probes (non-root minimum is 0.2).

    Returns:
        The argument vector.
    """
    return ["ping", "-n", "-c", str(count), "-i", str(max(interval, 0.2)), "-W", "2", host]


def ping(host: str, count: int, interval: float) -> Dict:
    """
    Ping a host and return the statistics (blocking).

    Args:
        host: Target host or IP.
        count: Probes to send.
        interval: Seconds between probes.

    Returns:
        The :func:`summarize_rtts` dict plus ``host``; ``error`` is set
        when ``ping`` could not run (e.g. DNS failure).
    """
    try:
        proc = subprocess.run(
            _ping_command(host, count, interval), capture_output=True, text=True,
            timeout=count * max(interval, 0.2) + 15,
        )
    except Exception as e:
        return {"host": host, "error": str(e), **summarize_rtts([], count)}
    result = {"host": host, **parse_ping_output(proc.stdout, count)}
    if not proc.stdout.strip():
        result["error"] = (proc.stderr or "ping produced no output").strip()
    return result


class PingSession:
    """
    Background ``ping`` used to measure latency while the line is
    loaded.

    Attributes:
        host: Target host or IP.
    """

    def __init__(self, host: str, interval: float = 0.2):
        """
        Initialize the session (call :meth:`start`).

        Args:
            host: Target host or IP.
            interval: Seconds between probes.
        """
        self.host = host
        self.interval = interval
        self._proc: Optional[subprocess.Popen] = None
        self._lines: List[str] = []
        self._reader: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start pinging until :meth:`stop` is called."""
        self._proc = subprocess.Popen(
            _ping_command(self.host, 100000, self.interval), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        """Collect stdout lines until the process exits."""
        for line in self._proc.stdout:
            self._lines.append(line)

    def stop(self) -> Dict:
        """
        Stop pinging (SIGINT, so ``ping`` prints its summary) and
        summarize.

        Returns:
            The :func:`summarize_rtts` dict plus ``host``. The probe
            still in flight when the session stops is not counted as
            lost.
        """
        if self._proc is None:
            return {"host": self.host, "error": "not started", **summarize_rtts([], 0)}
        self._proc.send_signal(signal.SIGINT)
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        if self._reader:
            self._reader.join(timeout=5)
        text = "".join(self._lines)
        replies = [(int(m.group(1)), float(m.group(2))) for m in PING_RTT_RE.finditer(text)]
        sent_match = PING_SENT_RE.search(text)
        last_seq = max((seq for seq, _ in replies), default=0)
        sent = int(sent_match.group(1)) if sent_match else last_seq
        if sent > last_seq:
            sent -= 1
        return {"host": self.host, **summarize_rtts([rtt for _, rtt in replies], max(sent, len(replies)))}


def mtr_report(target: str, cycles: int) -> Dict:
    """
    Run ``mtr`` in report mode and parse the per-hop statistics.

    Args:
        target: Host to trace.
        cycles: Probes per hop (one per second for non-root users).

    Returns:
        Dict with ``target`` and ``hops`` (list of ``{"hop", "host",
        "asn", "loss_pct", "sent", "avg", "best", "worst", "stdev"}``);
        ``error`` is set when ``mtr`` is missing or failed.
    """
    if not shutil.which("mtr"):
        return {"target": target, "hops": [], "error": "mtr is not installed"}
    try:
        proc = subprocess.run(
            ["mtr", "-j", "-z", "-c", str(cycles), target],
            capture_output=True, text=True, timeout=cycles * 3 + 60,
        )
        hubs = json.loads(proc.stdout)["report"]["hubs"]
    except Exception as e:
        return {"target": target, "hops": [], "error": f"mtr failed: {e}"}
    hops = [{
        "hop": h.get("count"),
        "host": h.get("host"),
        "asn": h.get("ASN"),
        "loss_pct": h.get("Loss%"),
        "sent": h.get("Snt"),
        "avg": h.get("Avg"),
        "best": h.get("Best"),
        "worst": h.get("Wrst"),
        "stdev": h.get("StDev"),
    } for h in hubs]
    return {"target": target, "hops": hops}
