"""
Result storage.

One JSON document per run under the results directory, named after the
run id (``YYYYmmdd-HHMMSS``). Writes are atomic (temp file +
``os.replace``) so the dashboard never reads a half-written run.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

RUN_ID_RE = re.compile(r"^\d{8}-\d{6}$")
"""Valid run ids (also guards against path traversal)."""

CSV_COLUMNS = (
    "id", "started_at", "label", "profile", "status", "public_ip", "interface",
    "best_download_mbps", "best_single_stream_download_mbps", "isp_cache_mbps", "local_mbps",
    "national_mbps", "international_mbps", "best_upload_mbps", "idle_latency_ms", "idle_loss_pct",
    "loaded_download_loss_pct", "loaded_download_bloat_ms", "loaded_upload_loss_pct",
    "loaded_upload_bloat_ms",
)
"""Columns of the CSV export (run metadata + summary metrics)."""


class ResultStore:
    """
    Directory of run documents.

    Attributes:
        directory: Where the JSON files live.
    """

    def __init__(self, directory: Path):
        """
        Args:
            directory: Results directory (created on demand).
        """
        self.directory = Path(directory)

    def _file(self, run_id: str) -> Path:
        """
        Path of a run document.

        Args:
            run_id: Run id.

        Returns:
            The file path.

        Raises:
            ValueError: On a malformed id.
        """
        if not RUN_ID_RE.match(run_id or ""):
            raise ValueError(f"Invalid run id '{run_id}'")
        return self.directory / f"{run_id}.json"

    def save(self, doc: Dict) -> None:
        """
        Persist a run document atomically.

        Args:
            doc: Run document with an ``id``.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self._file(doc["id"])
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, target)

    def get(self, run_id: str) -> Optional[Dict]:
        """
        Load a run document.

        Args:
            run_id: Run id.

        Returns:
            The document, or ``None`` when it does not exist.
        """
        path = self._file(run_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def delete(self, run_id: str) -> bool:
        """
        Delete a run document.

        Args:
            run_id: Run id.

        Returns:
            ``True`` when a file was removed.
        """
        path = self._file(run_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def all(self) -> List[Dict]:
        """
        Load every run document, newest first (unreadable files skipped).

        Returns:
            The documents.
        """
        docs = []
        for path in sorted(self.directory.glob("*.json"), reverse=True):
            try:
                docs.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return docs

    def list(self) -> List[Dict]:
        """
        Summaries of every run, newest first.

        Returns:
            Dicts with the run metadata and its ``summary``.
        """
        keys = ("id", "started_at", "finished_at", "label", "notes", "profile", "status", "error")
        return [{**{k: d.get(k) for k in keys}, "summary": d.get("summary") or {}} for d in self.all()]

    def to_csv(self) -> str:
        """
        Export the run summaries as CSV.

        Returns:
            CSV text with :data:`CSV_COLUMNS`.
        """
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for run in self.list():
            writer.writerow({**run["summary"], **{k: v for k, v in run.items() if k != "summary"}})
        return buf.getvalue()
