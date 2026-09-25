"""
Application settings.

Scalar settings come from environment variables, loaded from the
project ``.env`` file (see ``.env.template``). The test catalog
(targets, durations, services, thresholds, profiles) is structured data
and lives in the JSON file named by ``NSD_TESTS_FILE``. An optional,
unversioned local file (``NSD_LOCAL_TESTS_FILE``) is merged on top of it
for machine-specific entries such as private servers.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
"""Repository root; relative paths in the settings resolve against it."""

VERSION = "1.0.0"
"""Application version."""


def _path(value: str) -> Path:
    """
    Resolve a settings path against :data:`PROJECT_ROOT`.

    Args:
        value: Absolute or project-relative path.

    Returns:
        The absolute path.
    """
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass(frozen=True)
class Settings:
    """Resolved application settings."""

    host: str
    port: int
    plan_download_mbps: float
    plan_upload_mbps: float
    default_profile: str
    tests_file: Path
    local_tests_file: Path
    results_dir: Path
    log_file: Path
    log_level: str

    @property
    def plan(self) -> Dict[str, float]:
        """Contracted plan as consumed by the analyzer."""
        return {"download_mbps": self.plan_download_mbps, "upload_mbps": self.plan_upload_mbps}

    def load_tests(self) -> Dict:
        """
        Read the test catalog, merged with the local override file.

        Returns:
            The effective catalog (see :func:`deep_merge` for how the
            local file combines with the base one).

        Raises:
            ValueError: When a file is not valid JSON.
        """
        tests = _read_json(self.tests_file)
        if self.local_tests_file.exists():
            tests = deep_merge(tests, _read_json(self.local_tests_file))
        return tests

    def profile_names(self) -> list:
        """
        List the configured profiles.

        Returns:
            Profile names in file order.
        """
        return list((self.load_tests().get("profiles") or {}).keys())

    def resolve_profile(self, profile: str) -> Dict:
        """
        Build the effective test configuration of a profile.

        The profile block is deep-merged over the base sections; lists
        are replaced, not merged.

        Args:
            profile: Profile name.

        Returns:
            The merged configuration (without the ``profiles`` key).

        Raises:
            ValueError: When the profile does not exist.
        """
        tests = self.load_tests()
        profiles = tests.pop("profiles", {}) or {}
        if profile not in profiles:
            raise ValueError(f"Unknown profile '{profile}'. Available: {', '.join(profiles)}")
        return deep_merge(tests, profiles[profile] or {})


def _read_json(path: Path) -> Dict:
    """
    Read a JSON document.

    Args:
        path: File path.

    Returns:
        The parsed document.

    Raises:
        ValueError: When the file is not valid JSON (names the file).
    """
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: invalid JSON ({e})") from e


def _is_id_list(value) -> bool:
    """
    Tell whether a value is a list of dicts that all carry an ``id``.

    Args:
        value: Any value.

    Returns:
        ``True`` for id-keyed lists (targets, checks).
    """
    return isinstance(value, list) and bool(value) and all(isinstance(v, dict) and "id" in v for v in value)


def deep_merge(base: Dict, override: Dict) -> Dict:
    """
    Recursively merge ``override`` into a copy of ``base``.

    Nested dicts merge. Lists of dicts carrying an ``id`` merge by id:
    an override entry with a known id is merged into that entry, a new
    id is appended. Any other value (including plain lists) replaces.

    Args:
        base: Base document.
        override: Values that win.

    Returns:
        The merged copy.
    """
    out = copy.deepcopy(base)
    for key, value in override.items():
        current = out.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            out[key] = deep_merge(current, value)
        elif _is_id_list(value) and _is_id_list(current):
            merged = {item["id"]: item for item in current}
            for item in value:
                merged[item["id"]] = deep_merge(merged[item["id"]], item) if item["id"] in merged else copy.deepcopy(item)
            out[key] = list(merged.values())
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_settings() -> Settings:
    """
    Load ``.env`` (without overriding real environment variables) and
    build the settings.

    Returns:
        The resolved :class:`Settings`.
    """
    load_dotenv(PROJECT_ROOT / ".env")
    env = os.environ.get
    return Settings(
        host=env("NSD_HOST", "127.0.0.1"),
        port=int(env("NSD_PORT", "7071")),
        plan_download_mbps=float(env("NSD_PLAN_DOWNLOAD_MBPS", "0") or 0),
        plan_upload_mbps=float(env("NSD_PLAN_UPLOAD_MBPS", "0") or 0),
        default_profile=env("NSD_DEFAULT_PROFILE", "standard"),
        tests_file=_path(env("NSD_TESTS_FILE", "config/tests.json")),
        local_tests_file=_path(env("NSD_LOCAL_TESTS_FILE", "config/tests.local.json")),
        results_dir=_path(env("NSD_RESULTS_DIR", "data/results")),
        log_file=_path(env("NSD_LOG_FILE", "logs/netspeeddiag.log")),
        log_level=env("NSD_LOG_LEVEL", "INFO").upper(),
    )


def setup_logging(settings: Settings) -> None:
    """
    Log to stderr and to the configured file.

    Args:
        settings: Application settings.
    """
    settings.log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(settings.log_file, encoding="utf-8")],
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
