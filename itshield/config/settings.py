"""Centralized configuration for ITShield.

All paths, defaults and tunables are read here so every module can be
configured from a single place. Environment variables override the defaults
to make systemd deployment and CI testing easier.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _env_path(name: str, default: Path) -> Path:
    """Resolve a path from an env var, expanding ~ and resolving relative paths."""
    val = os.environ.get(name)
    if val:
        return Path(val).expanduser().resolve()
    return default.resolve()


@dataclass
class Settings:
    """Holds every tunable parameter of the ITShield runtime."""

    project_root: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[2]
    )

    data_dir: Path = field(default_factory=lambda: Path("data"))
    reports_dir: Path = field(default_factory=lambda: Path("reports"))
    signatures_dir: Path = field(default_factory=lambda: Path("signatures"))
    rules_dir: Path = field(default_factory=lambda: Path("rules"))

    db_path: Path = field(default_factory=lambda: Path("data/itshield.db"))

    signature_bank_path: Path = field(
        default_factory=lambda: Path("signatures/hashes.json")
    )

    yara_rules_path: Path = field(
        default_factory=lambda: Path("rules")
    )

    ipc_version: int = 1
    ipc_max_message_size: int = 1024 * 1024  # 1 MiB
    ipc_socket_path: Path = field(
        default_factory=lambda: Path("/tmp/itshield.sock")
    )

    scanner_max_file_size: int = 256 * 1024 * 1024  # 256 MiB
    scanner_chunk_size: int = 1024 * 1024  # 1 MiB
    scanner_follow_symlinks: bool = False
    scanner_yara_timeout_seconds: int = 30

    log_level: str = "INFO"
    log_format: str = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )

    def resolve(self) -> "Settings":
        """Resolve every relative path against project_root."""
        for name in (
            "data_dir",
            "reports_dir",
            "signatures_dir",
            "rules_dir",
            "db_path",
            "signature_bank_path",
            "yara_rules_path",
        ):
            value = getattr(self, name)
            if not value.is_absolute():
                setattr(self, name, (self.project_root / value).resolve())
        return self

    def ensure_dirs(self) -> None:
        """Create data, reports, signatures and rules directories if missing."""
        for d in (
            self.data_dir,
            self.reports_dir,
            self.signatures_dir,
            self.rules_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

    @property
    def ipc_socket_resolved(self) -> Path:
        """Resolve the IPC socket path, honoring XDG_RUNTIME_DIR on Linux.

        The original issue reported by the user was that the socket path was
        misinterpreted when ``XDG_RUNTIME_DIR`` was unset. We now fall back to
        ``/tmp`` only if neither XDG_RUNTIME_DIR nor an explicit override is set.
        """
        override = os.environ.get("ITSHIELD_IPC_SOCKET")
        if override:
            return Path(override).expanduser().resolve()

        xdg = os.environ.get("XDG_RUNTIME_DIR")
        if xdg:
            return Path(xdg) / "itshield.sock"

        return Path("/tmp/itshield.sock")


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Return a cached, fully-resolved Settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings().resolve()
        _settings.ensure_dirs()
    return _settings


def reload_settings() -> Settings:
    """Force re-reading of settings (used by tests)."""
    global _settings
    _settings = None
    return get_settings()
