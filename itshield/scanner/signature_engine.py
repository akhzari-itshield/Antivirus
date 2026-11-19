"""Signature Engine - SHA-256 lookup against the signature bank.

Section 9.3 of the architecture document.

The signature bank is a JSON file at ``signatures/hashes.json`` with the
schema::

    {
      "version": 1,
      "generated_at": "2026-11-17T00:00:00Z",
      "signatures": [
        {
          "sha256": "<64 hex chars>",
          "name": "EICAR-Test-File",
          "family": "Test",
          "severity": "LOW",
          "source": "eicar.org"
        },
        ...
      ]
    }

Future work (not in this version):
    * versioning, digital signature, signed update channel
    * binary format (packed hashes) for large banks
    * SQLite-backed cache via the ``signatures`` table
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from itshield.config.settings import get_settings
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SignatureMatch:
    """A positive signature match returned by :meth:`SignatureEngine.lookup`."""

    sha256: str
    name: str
    family: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None


class SignatureEngine:
    """Load and query the signature bank.

    The bank is fully loaded into an in-memory dict at construction time.
    For the educational sample bank this is fine; for a production bank with
    millions of entries a SQLite cache or a packed-hash structure would be
    used instead (see section 9.3 of the document).
    """

    def __init__(self, bank_path: Optional[str | Path] = None) -> None:
        settings = get_settings()
        self.bank_path = Path(bank_path) if bank_path else settings.signature_bank_path
        self._signatures: Dict[str, SignatureMatch] = {}
        self._hashes: set = set()  # Phase 15: for batch set-intersection lookups
        self._bank_version: Optional[int] = None
        self._bank_generated_at: Optional[str] = None
        self._load_status: str = "not_loaded"  # ok / missing / malformed / empty
        self._load()

    @property
    def load_status(self) -> str:
        """Return the status of the last bank load: ok/missing/malformed/empty."""
        return self._load_status

    def reload(self) -> None:
        """Re-read the signature bank from disk. Useful after updates."""
        self._signatures.clear()
        self._hashes.clear()
        self._bank_version = None
        self._bank_generated_at = None
        self._load_status = "not_loaded"
        self._load()

    def _load(self) -> None:
        if not self.bank_path.exists():
            self._load_status = "missing"
            logger.warning(
                "Signature bank not found at %s; engine will report no matches",
                self.bank_path,
            )
            return

        try:
            data = json.loads(self.bank_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            self._load_status = "malformed"
            logger.error("Failed to parse signature bank %s: %s", self.bank_path, exc)
            return

        if not isinstance(data, dict) or "signatures" not in data:
            self._load_status = "malformed"
            logger.error(
                "Signature bank %s is malformed (expected top-level 'signatures' array)",
                self.bank_path,
            )
            return

        self._bank_version = data.get("version")
        self._bank_generated_at = data.get("generated_at")
        sigs = data["signatures"]
        if not isinstance(sigs, list):
            self._load_status = "malformed"
            logger.error("Signature bank 'signatures' field is not a list")
            return

        _HEX_CHARS = set("0123456789abcdef")
        duplicates = 0
        for entry in sigs:
            try:
                sha = str(entry.get("sha256", "")).lower()
                if not sha:
                    logger.warning("Skipping signature entry with empty sha256: %r", entry)
                    continue
                if len(sha) != 64 or not all(c in _HEX_CHARS for c in sha):
                    logger.warning(
                        "Skipping signature with invalid sha256 (len=%d): %s...",
                        len(sha), sha[:16],
                    )
                    continue
                if sha in self._signatures:
                    duplicates += 1
                    continue
                match = SignatureMatch(
                    sha256=sha,
                    name=entry.get("name", "Unknown"),
                    family=entry.get("family"),
                    severity=entry.get("severity"),
                    source=entry.get("source"),
                )
                self._signatures[sha] = match
                self._hashes.add(sha)
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning("Skipping malformed signature entry %r: %s", entry, exc)

        if duplicates > 0:
            logger.info("Skipped %d duplicate signatures", duplicates)

        if len(self._signatures) == 0:
            self._load_status = "empty"
        else:
            self._load_status = "ok"

        logger.info(
            "Loaded %d signatures from %s (version=%s, generated_at=%s, status=%s)",
            len(self._signatures),
            self.bank_path,
            self._bank_version,
            self._bank_generated_at,
            self._load_status,
        )

    def lookup(self, sha256: str) -> Optional[SignatureMatch]:
        """Return the matching :class:`SignatureMatch` or ``None``."""
        return self._signatures.get(sha256.lower())

    def __contains__(self, sha256: str) -> bool:
        return sha256.lower() in self._signatures

    def __len__(self) -> int:
        return len(self._signatures)

    def to_list(self) -> List[Dict[str, str]]:
        """Return all signatures as plain dicts (used by tests and IPC)."""
        return [
            {
                "sha256": m.sha256,
                "name": m.name,
                "family": m.family or "",
                "severity": m.severity or "",
                "source": m.source or "",
            }
            for m in self._signatures.values()
        ]

    @property
    def bank_version(self) -> Optional[int]:
        return self._bank_version

    @property
    def bank_generated_at(self) -> Optional[str]:
        return self._bank_generated_at
