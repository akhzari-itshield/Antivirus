"""Settings export/import for ITShield (Phase 11).

Save the current :class:`Settings` to a JSON file and load it back.
Useful for:
    * backing up configuration before a risky update
    * copying configuration between machines
    * resetting to a known-good state

The exported file contains every public field of :class:`Settings`
except paths that are machine-specific (the IPC socket path is
re-derived on load from XDG_RUNTIME_DIR).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from itshield.config.settings import Settings, get_settings
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


def export_settings(path: str | Path, settings: Settings | None = None) -> Path:
    """Write the current settings to ``path`` as JSON. Returns the path."""
    s = settings or get_settings()
    data: Dict[str, Any] = {
        "version": 1,
        "exported_at": _now_iso(),
        "settings": {
            "scanner_max_file_size": s.scanner_max_file_size,
            "scanner_chunk_size": s.scanner_chunk_size,
            "scanner_follow_symlinks": s.scanner_follow_symlinks,
            "scanner_yara_timeout_seconds": s.scanner_yara_timeout_seconds,
            "ipc_version": s.ipc_version,
            "ipc_max_message_size": s.ipc_max_message_size,
            "log_level": s.log_level,
            "log_format": s.log_format,
            "signature_bank_path": _rel_or_abs(s.signature_bank_path, s.project_root),
            "yara_rules_path": _rel_or_abs(s.yara_rules_path, s.project_root),
            "db_path": _rel_or_abs(s.db_path, s.project_root),
        },
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Exported settings to %s", path)
    return path


def import_settings(path: str | Path, apply: bool = True) -> Dict[str, Any]:
    """Load settings from ``path`` and optionally apply them to the live config.

    Returns the parsed settings dict.
    """
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if "settings" not in data:
        raise ValueError(f"Invalid settings file: missing 'settings' key")
    settings_data = data["settings"]

    if apply:
        s = get_settings()
        if "scanner_max_file_size" in settings_data:
            s.scanner_max_file_size = int(settings_data["scanner_max_file_size"])
        if "scanner_chunk_size" in settings_data:
            s.scanner_chunk_size = int(settings_data["scanner_chunk_size"])
        if "scanner_follow_symlinks" in settings_data:
            s.scanner_follow_symlinks = bool(settings_data["scanner_follow_symlinks"])
        if "scanner_yara_timeout_seconds" in settings_data:
            s.scanner_yara_timeout_seconds = int(settings_data["scanner_yara_timeout_seconds"])
        if "ipc_max_message_size" in settings_data:
            s.ipc_max_message_size = int(settings_data["ipc_max_message_size"])
        if "log_level" in settings_data:
            s.log_level = str(settings_data["log_level"])
        if "signature_bank_path" in settings_data:
            p = Path(str(settings_data["signature_bank_path"]))
            if not p.is_absolute():
                p = (s.project_root / p).resolve()
            s.signature_bank_path = p
        if "yara_rules_path" in settings_data:
            p = Path(str(settings_data["yara_rules_path"]))
            if not p.is_absolute():
                p = (s.project_root / p).resolve()
            s.yara_rules_path = p
        if "db_path" in settings_data:
            p = Path(str(settings_data["db_path"]))
            if not p.is_absolute():
                p = (s.project_root / p).resolve()
            s.db_path = p
        logger.info("Imported settings from %s and applied to live config", path)

    return settings_data


def _rel_or_abs(path: Path, base: Path) -> str:
    """Return ``path`` relative to ``base`` when possible, else absolute."""
    try:
        return str(Path(path).relative_to(base))
    except ValueError:
        return str(path)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
