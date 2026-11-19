"""YARA rule downloader for ITShield (Phase 9).

Pulls YARA rule collections from GitHub (default: neo23x0/signature-base)
and merges the ``.yar`` files into the local rules directory so the
:class:`~itshield.scanner.yara_engine.YaraEngine` picks them up on the
next scan.

The neo23x0/signature-base repository is a curated, open-source YARA
rule collection maintained by Florian Roth. It contains:
    * `yara/`            - generic YARA rules (the main set we want)
    * `malware/`         - malware-family-specific YARA rules
    * `iocs/`            - indicators of compromise (we skip these)
    * `misc/`            - helper rules

This downloader focuses on the ``yara/`` and ``malware/`` directories.

Flow:
    1. Download the repo as a ZIP archive via :class:`GitHubArchiveSource`.
    2. Extract it in memory with :mod:`zipfile`.
    3. Walk the archive for ``.yar`` files in the target subdirectories.
    4. Copy each file to ``rules_dir/neo23x0_*.yar`` (prefix avoids
       collisions with the project's own ``sample.yar``).
    5. Record the operation in ``update_history`` (component=yara_rules).

The downloader never overwrites the user's own ``sample.yar`` or any
file not prefixed with ``neo23x0_`` so user-defined rules are safe.
"""

from __future__ import annotations

import io
import os
import shutil
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from itshield.logging.logger import get_logger
from itshield.storage.database import Database
from itshield.update.http_source import GitHubArchiveSource, DownloadResult

logger = get_logger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


DEFAULT_REPO = "neo23x0/signature-base"
DEFAULT_REF = "master"
DEFAULT_SUBDIRS = ("yara", "malware")

_SKIP_FILES = {
    "base_index.yar",
    "malware_index.yar",
    "thor_inverse_matches.yar",
}


@dataclass
class YaraDownloadResult:
    """Outcome of a YARA rule download + merge operation."""

    success: bool
    repo: str
    ref: str
    archive_bytes: int = 0
    archive_sha256: str = ""
    rules_downloaded: int = 0
    rules_skipped: int = 0
    saved_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timestamp: str = ""
    status: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "repo": self.repo,
            "ref": self.ref,
            "archive_bytes": self.archive_bytes,
            "archive_sha256": self.archive_sha256,
            "rules_downloaded": self.rules_downloaded,
            "rules_skipped": self.rules_skipped,
            "saved_files": self.saved_files,
            "errors": self.errors,
            "timestamp": self.timestamp,
            "status": self.status,
        }


class YaraRuleDownloader:
    """Downloads YARA rules from a GitHub repo and merges them locally."""

    COMPONENT = "yara_rules"

    def __init__(
        self,
        db: Database,
        rules_dir: str | Path,
        repo: str = DEFAULT_REPO,
        ref: str = DEFAULT_REF,
        subdirs: tuple[str, ...] = DEFAULT_SUBDIRS,
        file_prefix: str = "neo23x0_",
        github_source: Optional[GitHubArchiveSource] = None,
    ) -> None:
        self._db = db
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.repo = repo
        self.ref = ref
        self.subdirs = subdirs
        self.file_prefix = file_prefix
        self._source = github_source or GitHubArchiveSource(repo=repo, ref=ref)

    def download_and_merge(self) -> YaraDownloadResult:
        """Download the repo archive and merge its .yar files into rules_dir."""
        timestamp = _utcnow()
        result = YaraDownloadResult(
            success=False, repo=self.repo, ref=self.ref, timestamp=timestamp,
        )

        tmp_dir = Path(self.rules_dir) / ".downloads"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        archive_path = tmp_dir / f"{self.repo.replace('/', '_')}_{self.ref}.zip"

        logger.info("Downloading YARA rules from %s (ref=%s)...", self.repo, self.ref)
        dl = self._source.download(archive_path)
        if not dl.success:
            result.status = dl.status
            result.errors.append(dl.detail)
            self._record_history(result, status="FAILED_DOWNLOAD")
            return result

        result.archive_bytes = dl.bytes_downloaded
        result.archive_sha256 = dl.sha256

        try:
            saved, skipped, errors = self._extract_rules_from_zip(archive_path)
        except Exception as exc:
            result.errors.append(f"extract error: {exc}")
            result.status = "EXTRACT_ERROR"
            self._record_history(result, status="FAILED_EXTRACT")
            archive_path.unlink(missing_ok=True)
            return result

        result.rules_downloaded = len(saved)
        result.rules_skipped = len(skipped)
        result.saved_files = saved
        result.errors.extend(errors)
        result.success = len(saved) > 0
        result.status = "OK" if result.success else "NO_RULES_FOUND"

        history_status = "APPLIED" if result.success else "NO_RULES_FOUND"
        self._record_history(result, status=history_status)

        archive_path.unlink(missing_ok=True)
        try:
            tmp_dir.rmdir()
        except OSError:
            pass  # may still contain other downloads

        logger.info(
            "YARA download done: %d rules merged, %d skipped, %d errors",
            result.rules_downloaded, result.rules_skipped, len(result.errors),
        )
        return result

    def list_downloaded_rules(self) -> List[dict]:
        """List all .yar files in rules_dir that match our prefix."""
        out = []
        for p in sorted(self.rules_dir.glob(f"{self.file_prefix}*.yar")):
            try:
                stat = p.stat()
                out.append({
                    "filename": p.name,
                    "path": str(p),
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
                })
            except OSError:
                continue
        return out

    def clear_downloaded_rules(self) -> int:
        """Remove every prefixed .yar file (user's own rules are untouched)."""
        removed = 0
        for p in self.rules_dir.glob(f"{self.file_prefix}*.yar"):
            try:
                p.unlink()
                removed += 1
            except OSError as exc:
                logger.warning("Could not remove %s: %s", p, exc)
        logger.info("Cleared %d downloaded YARA rule files", removed)
        return removed

    def _extract_rules_from_zip(
        self, archive_path: Path,
    ) -> tuple[List[str], List[str], List[str]]:
        """Walk a ZIP archive and copy .yar files from the target subdirs.

        Returns (saved_filenames, skipped_filenames, errors).
        """
        saved: List[str] = []
        skipped: List[str] = []
        errors: List[str] = []

        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                parts = name.split("/")
                if len(parts) < 3:
                    continue
                if parts[1] not in self.subdirs:
                    continue
                fname = parts[-1]
                if not fname.lower().endswith(".yar"):
                    continue
                if fname in _SKIP_FILES:
                    skipped.append(fname)
                    continue

                dest_name = f"{self.file_prefix}{fname}"
                dest_path = self.rules_dir / dest_name
                try:
                    with zf.open(info) as src, dest_path.open("wb") as dst:
                        dst.write(src.read())
                    saved.append(dest_name)
                except Exception as exc:
                    errors.append(f"{fname}: {exc}")

        return saved, skipped, errors

    def _record_history(self, result: YaraDownloadResult, status: str) -> None:
        """Insert a row in update_history describing this YARA download."""
        try:
            details = (
                f"repo={result.repo}/{result.ref}, "
                f"rules={result.rules_downloaded}, skipped={result.rules_skipped}, "
                f"archive_bytes={result.archive_bytes}, "
                f"sha256={result.archive_sha256[:12]}.."
            )
            if result.errors:
                details += f", errors={result.errors[:3]}"
            self._db.execute(
                """
                INSERT INTO update_history
                    (applied_at, component, from_version, to_version, status, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.timestamp,
                    self.COMPONENT,
                    None,
                    None,
                    status,
                    details,
                ),
            )
        except Exception:
            logger.exception("Could not record YARA download history")
