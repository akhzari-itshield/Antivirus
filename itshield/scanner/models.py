"""Data models for the scanner subsystem.

These dataclasses are the lingua franca between the Hash, Signature, YARA,
File Analyzer, Scanner and Detection Engine modules. They are intentionally
plain Python (no ORM, no Pydantic) so they stay cheap to construct and
easy to serialize to JSON for IPC.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class DetectionVerdict(str, Enum):
    """Possible outcomes of scanning a single file.

    Section 10 of the architecture document.
    A separate ``SKIPPED`` value is added for files that the scanner never
    opened (too big, symlink to skipped, permission denied, ...).
    """

    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    SKIPPED = "SKIPPED"


@dataclass
class FileResult:
    """Everything the scanner learned about one file."""

    file_path: str
    file_size: int = 0
    file_type: Optional[str] = None      # detected via Magic Bytes
    sha256: Optional[str] = None
    verdict: DetectionVerdict = DetectionVerdict.UNKNOWN
    matched_signature: Optional[str] = None
    matched_yara_rules: List[str] = field(default_factory=list)
    entropy: Optional[float] = None
    reason: str = ""
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


@dataclass
class ScanProgress:
    """Live progress emitted via the scanner's progress callback."""

    job_id: str
    files_total: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    current_path: Optional[str] = None
    bytes_processed: int = 0
    percent: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanStats:
    """Aggregate counts produced at the end of a scan job."""

    job_id: str
    target_path: str
    files_total: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_clean: int = 0
    files_unknown: int = 0
    files_suspicious: int = 0
    files_malicious: int = 0
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanRequest:
    """Input parameters for a scan job (used by Scan Manager / IPC)."""

    target_path: str
    recursive: bool = True
    follow_symlinks: bool = False
    max_file_size: Optional[int] = None
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @classmethod
    def from_path(cls, path: str | Path, **kwargs: Any) -> "ScanRequest":
        return cls(target_path=str(Path(path).expanduser().resolve()), **kwargs)
