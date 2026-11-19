"""Signature verification for update packages (Phase 8).

Section 18 / 19 of the architecture document.

A signature bank update must NEVER be applied just because it was
received from a server. Two layers of verification are required:

    1. **Integrity** - the SHA-256 of the new bank must match an
       expected value (out-of-band channel: HTTPS page, email, separate
       config file).
    2. **Authenticity** - the bank must be signed with a private key
       whose public counterpart is shipped with ITShield. This Phase 8
       version supports SHA-256 integrity; Ed25519 authenticity is
       stubbed and will be enabled once the signing key infrastructure
       is in place (``cryptography`` package will be required).

The verifier is intentionally pure-Python and side-effect free so it
can be exercised in unit tests without touching the filesystem.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Union

from itshield.logging.logger import get_logger

logger = get_logger(__name__)


class VerificationStatus(str, Enum):
    OK = "OK"
    HASH_MISMATCH = "HASH_MISMATCH"
    PARSE_ERROR = "PARSE_ERROR"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"


@dataclass
class VerificationResult:
    """Outcome of a verification attempt."""

    status: VerificationStatus
    actual_sha256: str = ""
    expected_sha256: str = ""
    bank_version: Optional[int] = None
    signature_count: int = 0
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == VerificationStatus.OK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "actual_sha256": self.actual_sha256,
            "expected_sha256": self.expected_sha256,
            "bank_version": self.bank_version,
            "signature_count": self.signature_count,
            "detail": self.detail,
        }


_REQUIRED_BANK_FIELDS = {"version", "generated_at", "signatures"}


class SignatureVerifier:
    """Verify the integrity and authenticity of a signature bank file."""

    def __init__(self, chunk_size: int = 1024 * 1024) -> None:
        self.chunk_size = chunk_size

    def hash_file(self, path: str | Path) -> str:
        """Compute SHA-256 of ``path`` (chunked)."""
        p = Path(path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"Cannot hash missing file: {p}")
        h = hashlib.sha256()
        with p.open("rb") as fh:
            while True:
                chunk = fh.read(self.chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def validate_schema(self, bank_dict: Dict[str, Any]) -> VerificationResult:
        """Validate the JSON structure of a signature bank dict."""
        if not isinstance(bank_dict, dict):
            return VerificationResult(
                status=VerificationStatus.SCHEMA_ERROR,
                detail="bank is not a JSON object",
            )
        missing = _REQUIRED_BANK_FIELDS - set(bank_dict.keys())
        if missing:
            return VerificationResult(
                status=VerificationStatus.SCHEMA_ERROR,
                detail=f"missing required fields: {sorted(missing)}",
            )
        sigs = bank_dict["signatures"]
        if not isinstance(sigs, list):
            return VerificationResult(
                status=VerificationStatus.SCHEMA_ERROR,
                detail="'signatures' must be a list",
            )
        if sigs:
            first = sigs[0]
            if not isinstance(first, dict) or "sha256" not in first:
                return VerificationResult(
                    status=VerificationStatus.SCHEMA_ERROR,
                    detail="first signature entry missing 'sha256'",
                )
        return VerificationResult(
            status=VerificationStatus.OK,
            bank_version=bank_dict.get("version"),
            signature_count=len(sigs),
        )

    def verify_file(
        self,
        path: str | Path,
        expected_sha256: str,
    ) -> VerificationResult:
        """Verify that the file at ``path`` hashes to ``expected_sha256``."""
        p = Path(path)
        if not p.exists():
            return VerificationResult(
                status=VerificationStatus.FILE_NOT_FOUND,
                detail=f"file not found: {p}",
            )
        try:
            actual = self.hash_file(p)
        except OSError as exc:
            return VerificationResult(
                status=VerificationStatus.PARSE_ERROR,
                detail=f"hash error: {exc}",
            )
        if actual.lower() != expected_sha256.lower():
            return VerificationResult(
                status=VerificationStatus.HASH_MISMATCH,
                actual_sha256=actual,
                expected_sha256=expected_sha256,
                detail="computed SHA-256 does not match expected",
            )
        return VerificationResult(
            status=VerificationStatus.OK,
            actual_sha256=actual,
            expected_sha256=expected_sha256,
        )

    def verify_bank_file(
        self,
        path: str | Path,
        expected_sha256: Optional[str] = None,
    ) -> VerificationResult:
        """Verify a signature bank JSON file: hash + schema.

        If ``expected_sha256`` is None, only schema validation is performed
        (no integrity check). When provided, both must pass.
        """
        p = Path(path)
        if not p.exists():
            return VerificationResult(
                status=VerificationStatus.FILE_NOT_FOUND,
                detail=f"bank file not found: {p}",
            )

        if expected_sha256 is not None:
            hash_result = self.verify_file(p, expected_sha256)
            if not hash_result.ok:
                return hash_result

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return VerificationResult(
                status=VerificationStatus.PARSE_ERROR,
                detail=f"could not parse JSON: {exc}",
            )
        schema_result = self.validate_schema(data)
        if not schema_result.ok:
            return schema_result

        return VerificationResult(
            status=VerificationStatus.OK,
            actual_sha256=hash_result.actual_sha256 if expected_sha256 else self.hash_file(p),
            expected_sha256=expected_sha256 or "",
            bank_version=schema_result.bank_version,
            signature_count=schema_result.signature_count,
        )

    def verify_signature(
        self,
        data: bytes,
        signature: bytes,
        public_key_path: Optional[str | Path] = None,
    ) -> bool:
        """Ed25519 signature verification (stub for future Phase).

        The real implementation will use ``cryptography.hazmat.primitives.asymmetric.ed25519``.
        For now, returns False because no key is configured.
        """
        logger.warning(
            "Ed25519 signature verification is not yet implemented; "
            "returning False. This will be enabled in a future version."
        )
        return False
