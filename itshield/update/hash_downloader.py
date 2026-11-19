"""Hash bank downloader for ITShield (Phase 10).

Section 18 of the architecture document - "دریافت نسخه جدید بانک امضاها".

Complements the YARA rule downloader (Phase 9) by pulling SHA-256
hashes of known malware from public threat-intelligence feeds and
merging them into the local ``signatures/hashes.json`` bank.

Supported sources:
    * :class:`MalwareBazaarSource` - queries the abuse.ch MalwareBazaar
      API (https://bazaar.abuse.ch/api/v1/) for recent malware samples.
      No API key required; returns up to 1000 recent SHA-256 hashes per
      call along with signature (family) names and tags.

Flow:
    1. Fetch recent hashes from the source (HTTP POST for MalwareBazaar).
    2. Read the current ``hashes.json`` bank.
    3. Merge new hashes (skip ones already present).
    4. Backup the current bank to ``data/bank_backups/``.
    5. Write the merged bank with an incremented version number.
    6. Record the operation in ``update_history`` (component=hash_bank).
"""

from __future__ import annotations

import json
import shutil
import time
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from itshield.logging.logger import get_logger
from itshield.storage.database import Database
from itshield.update.http_source import DEFAULT_USER_AGENT

logger = get_logger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class HashDownloadResult:
    """Outcome of a hash bank download + merge."""

    success: bool
    source: str
    hashes_fetched: int = 0
    hashes_added: int = 0          # new hashes actually merged
    hashes_duplicate: int = 0      # already in the bank, skipped
    bank_version_before: Optional[int] = None
    bank_version_after: Optional[int] = None
    bank_size_before: int = 0
    bank_size_after: int = 0
    timestamp: str = ""
    status: str = ""
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "source": self.source,
            "hashes_fetched": self.hashes_fetched,
            "hashes_added": self.hashes_added,
            "hashes_duplicate": self.hashes_duplicate,
            "bank_version_before": self.bank_version_before,
            "bank_version_after": self.bank_version_after,
            "bank_size_before": self.bank_size_before,
            "bank_size_after": self.bank_size_after,
            "timestamp": self.timestamp,
            "status": self.status,
            "errors": self.errors,
        }


class HashSource:
    """Abstract source of SHA-256 malware hashes."""

    name: str = "abstract"

    def fetch_hashes(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Return a list of dicts with at least ``sha256`` and ``name`` keys.

        Each dict may also carry ``family``, ``severity``, ``tags``, ``source``
        for richer metadata in the bank.
        """
        raise NotImplementedError


class MalwareBazaarSource(HashSource):
    """Queries abuse.ch MalwareBazaar for recent malware samples.

    API: POST https://mbazaar.abuse.ch/api/v1/
    Body: query=get_recent&selector=<n>  (n = number of samples, max 1000)
    Response: JSON { "query_status": "OK", "data": [ {sha256_hash, signature, ...}, ... ] }
    """

    name = "MalwareBazaar"
    API_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 30.0,
        api_key: Optional[str] = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.api_key = api_key

    def fetch_hashes(self, limit: int = 1000) -> List[Dict[str, Any]]:
        if limit > 1000:
            limit = 1000
        try:
            return self._fetch_via_api(limit)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                logger.info(
                    "MalwareBazaar API returned 401 (auth required); "
                    "falling back to CSV export"
                )
                return self._fetch_via_csv(limit)
            raise
        except urllib.error.URLError as exc:
            logger.warning(
                "MalwareBazaar API unreachable (%s); trying CSV export", exc
            )
            return self._fetch_via_csv(limit)

    def _fetch_via_api(self, limit: int) -> List[Dict[str, Any]]:
        """Fetch via the JSON API (requires Auth-Key for some queries)."""
        body = urllib.parse.urlencode({
            "query": "get_recent",
            "selector": str(limit),
        }).encode("utf-8")
        headers = {
            "User-Agent": self.user_agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        req = urllib.request.Request(
            self.API_URL, data=body, method="POST", headers=headers,
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))

        if payload.get("query_status") != "OK":
            raise RuntimeError(
                f"MalwareBazaar query failed: {payload.get('query_status')}"
            )

        samples = payload.get("data", [])
        if not isinstance(samples, list):
            return []

        result: List[Dict[str, Any]] = []
        for s in samples[:limit]:
            sha = s.get("sha256_hash")
            if not sha or not isinstance(sha, str) or len(sha) != 64:
                continue
            sig = s.get("signature") or "Unknown"
            result.append({
                "sha256": sha.lower(),
                "name": f"MalwareBazaar:{sig}",
                "family": sig if sig != "Unknown" else None,
                "severity": "HIGH",
                "source": "MalwareBazaar",
                "tags": (s.get("tags") or [])[:5],
                "first_seen": s.get("first_seen", ""),
            })
        return result

    def _fetch_via_csv(self, limit: int) -> List[Dict[str, Any]]:
        """Fetch via the daily CSV export (no auth required).

        URL: https://bazaar.abuse.ch/export/csv/recent/full/
        The CSV has columns including sha256_hash and signature.
        """
        import csv as csv_module
        import io
        csv_url = "https://bazaar.abuse.ch/export/csv/recent/full/"
        req = urllib.request.Request(
            csv_url,
            headers={"User-Agent": self.user_agent, "Accept": "text/csv"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout * 2) as response:
            content = response.read().decode("utf-8", errors="replace")

        result: List[Dict[str, Any]] = []
        reader = csv_module.reader(io.StringIO(content))
        for row in reader:
            if not row or len(row) < 10:
                continue
            sha = row[1].strip().lower() if len(row) > 1 else ""
            if len(sha) != 64 or not all(c in "0123456789abcdef" for c in sha):
                continue
            sig = row[7].strip() if len(row) > 7 else "Unknown"
            if not sig:
                sig = "Unknown"
            result.append({
                "sha256": sha,
                "name": f"MalwareBazaar:{sig}",
                "family": sig if sig != "Unknown" else None,
                "severity": "HIGH",
                "source": "MalwareBazaar",
                "tags": [],
                "first_seen": row[0].strip() if row[0] else "",
            })
            if len(result) >= limit:
                break
        logger.info("CSV fallback: fetched %d hashes", len(result))
        return result


class HashBankDownloader:
    """Downloads hashes from a :class:`HashSource` and merges them into the bank."""

    COMPONENT = "hash_bank"

    def __init__(
        self,
        db: Database,
        bank_path: str | Path,
        backup_dir: str | Path,
        source: Optional[HashSource] = None,
    ) -> None:
        self._db = db
        self.bank_path = Path(bank_path)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.source = source or MalwareBazaarSource()

    def download_and_merge(self, limit: int = 1000) -> HashDownloadResult:
        """Fetch hashes from the source and merge into the local bank."""
        timestamp = _utcnow()
        result = HashDownloadResult(
            success=False, source=self.source.name, timestamp=timestamp,
        )

        try:
            fetched = self.source.fetch_hashes(limit=limit)
        except Exception as exc:
            result.errors.append(f"fetch error: {exc}")
            result.status = "FETCH_ERROR"
            self._record_history(result, status="FAILED_FETCH")
            logger.exception("Hash fetch failed")
            return result

        result.hashes_fetched = len(fetched)
        if result.hashes_fetched == 0:
            result.status = "NO_HASHES"
            self._record_history(result, status="NO_HASHES")
            return result

        bank_data = self._read_current_bank()
        result.bank_version_before = bank_data.get("version")
        result.bank_size_before = len(bank_data.get("signatures", []))
        existing_hashes = {
            s["sha256"].lower() for s in bank_data.get("signatures", [])
            if isinstance(s, dict) and "sha256" in s
        }

        new_signatures = []
        for entry in fetched:
            sha = entry["sha256"]
            if sha in existing_hashes:
                result.hashes_duplicate += 1
                continue
            sig_entry = {
                "sha256": sha,
                "name": entry.get("name", "Unknown"),
                "family": entry.get("family"),
                "severity": entry.get("severity", "HIGH"),
                "source": entry.get("source", self.source.name),
            }
            if entry.get("tags"):
                sig_entry["tags"] = entry["tags"]
            if entry.get("first_seen"):
                sig_entry["first_seen"] = entry["first_seen"]
            new_signatures.append(sig_entry)
            existing_hashes.add(sha)

        result.hashes_added = len(new_signatures)
        if result.hashes_added == 0:
            result.status = "NO_NEW_HASHES"
            result.bank_version_after = result.bank_version_before
            result.bank_size_after = result.bank_size_before
            self._record_history(result, status="NO_NEW_HASHES")
            logger.info("No new hashes to add (%d duplicates)", result.hashes_duplicate)
            return result

        if self.bank_path.exists():
            backup_path = self.backup_dir / f"hashes_backup_{int(time.time())}.json"
            try:
                shutil.copy2(self.bank_path, backup_path)
                logger.info("Backed up current hash bank to %s", backup_path)
            except OSError as exc:
                result.errors.append(f"backup failed: {exc}")
                result.status = "BACKUP_FAILED"
                self._record_history(result, status="FAILED_BACKUP")
                return result

        new_version = (result.bank_version_before or 0) + 1
        merged_bank = {
            "version": new_version,
            "generated_at": timestamp,
            "source": "ITShield merged bank (local + MalwareBazaar)",
            "description": (
                f"Merged bank: {result.bank_size_before} original + "
                f"{result.hashes_added} new from {self.source.name}"
            ),
            "signatures": bank_data.get("signatures", []) + new_signatures,
        }
        try:
            self.bank_path.write_text(
                json.dumps(merged_bank, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            result.errors.append(f"write failed: {exc}")
            result.status = "WRITE_FAILED"
            self._record_history(result, status="FAILED_WRITE")
            return result

        result.bank_version_after = new_version
        result.bank_size_after = len(merged_bank["signatures"])
        result.success = True
        result.status = "APPLIED"
        self._record_history(result, status="APPLIED")

        logger.info(
            "Hash bank updated: v%s -> v%s (%d + %d = %d signatures, %d duplicates)",
            result.bank_version_before, new_version,
            result.bank_size_before, result.hashes_added, result.bank_size_after,
            result.hashes_duplicate,
        )
        return result

    def _read_current_bank(self) -> Dict[str, Any]:
        """Read and parse the current hash bank. Returns an empty structure if missing/bad."""
        if not self.bank_path.exists():
            return {"version": 0, "generated_at": "", "signatures": []}
        try:
            data = json.loads(self.bank_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {"version": 0, "generated_at": "", "signatures": []}
            if "signatures" not in data or not isinstance(data["signatures"], list):
                data["signatures"] = []
            return data
        except (json.JSONDecodeError, OSError):
            return {"version": 0, "generated_at": "", "signatures": []}

    def _record_history(self, result: HashDownloadResult, status: str) -> None:
        try:
            details = (
                f"source={result.source}, fetched={result.hashes_fetched}, "
                f"added={result.hashes_added}, duplicates={result.hashes_duplicate}, "
                f"v{result.bank_version_before}->v{result.bank_version_after}"
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
                    str(result.bank_version_before) if result.bank_version_before is not None else None,
                    str(result.bank_version_after) if result.bank_version_after is not None else None,
                    status,
                    details,
                ),
            )
        except Exception:
            logger.exception("Could not record hash bank history")
