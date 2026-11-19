"""IOC downloader for ITShield (Phase 12).

Section 18 of the architecture document - "دریافت به‌روزرسانی".

Pulls Indicators of Compromise (IOCs) from multiple public threat-
intelligence feeds and stores them in dedicated SQLite tables so the
Network Monitor and Scanner can match against them in real time.

Supported feeds (all from abuse.ch, no API key required):
    * :class:`ThreatFoxSource`   - IOCs (SHA-256, IPs, domains) from ThreatFox
      API: POST https://threatfox-api.abuse.ch/api/v1/  body: query=get_recent
    * :class:`URLHausSource`     - malicious URLs from URLHaus
      API: POST https://urlhaus-api.abuse.ch/v1/payloads/
    * :class:`FeodoTrackerSource`- botnet C2 IP addresses from Feodo Tracker
      API: GET https://feodotracker.abuse.ch/downloads/ipblocklist.json

Each source returns a list of IOC dicts that the :class:`IOCDownloader`
inserts into the appropriate table (ioc_hashes / ioc_ips / ioc_domains /
ioc_urls). Duplicates are skipped via UNIQUE constraints.
"""

from __future__ import annotations

import json
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
class IOCDownloadResult:
    """Outcome of an IOC feed download + merge."""

    success: bool
    source: str
    iocs_fetched: int = 0
    iocs_added: int = 0
    iocs_duplicate: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)  # {"hash": 5, "ip": 3, ...}
    timestamp: str = ""
    status: str = ""
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "source": self.source,
            "iocs_fetched": self.iocs_fetched,
            "iocs_added": self.iocs_added,
            "iocs_duplicate": self.iocs_duplicate,
            "by_type": self.by_type,
            "timestamp": self.timestamp,
            "status": self.status,
            "errors": self.errors,
        }


class IOCSource:
    """Abstract source of IOCs."""

    name: str = "abstract"

    def fetch(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Return a list of IOC dicts.

        Each dict must have at least ``ioc_type`` (one of: hash, ip, domain, url)
        and ``value``. It may also carry ``threat_name``, ``first_seen``, ``port``.
        """
        raise NotImplementedError


class ThreatFoxSource(IOCSource):
    """abuse.ch ThreatFox - IOC database (hashes, IPs, domains).

    API: POST https://threatfox-api.abuse.ch/api/v1/
    Body: {"query": "get_recent", "days": 7}  (JSON)
    Returns ioc_type values like "sha256", "ip:port", "domain".
    """

    name = "ThreatFox"
    API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, user_agent: str = DEFAULT_USER_AGENT, timeout: float = 30.0) -> None:
        self.user_agent = user_agent
        self.timeout = timeout

    def fetch(self, limit: int = 1000) -> List[Dict[str, Any]]:
        body = json.dumps({"query": "get_recent", "days": 7}).encode("utf-8")
        req = urllib.request.Request(
            self.API_URL,
            data=body,
            method="POST",
            headers={
                "User-Agent": self.user_agent,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))

        if payload.get("query_status") != "OK":
            raise RuntimeError(
                f"ThreatFox query failed: {payload.get('query_status', 'unknown')}"
            )

        data = payload.get("data", [])
        if not isinstance(data, list):
            return []

        results: List[Dict[str, Any]] = []
        for entry in data[:limit]:
            ioc_value = entry.get("ioc_value", "")
            ioc_type = entry.get("ioc_type", "")
            threat = entry.get("threat_name", "Unknown")
            first_seen = entry.get("first_seen_utc", "")
            if not ioc_value or not ioc_type:
                continue

            if ioc_type == "sha256":
                if len(ioc_value) == 64:
                    results.append({
                        "ioc_type": "hash", "value": ioc_value.lower(),
                        "threat_name": threat, "first_seen": first_seen,
                    })
            elif ioc_type in ("ip:port", "ip"):
                port = None
                ip = ioc_value
                if ":" in ioc_value and not ioc_value.startswith("["):
                    parts = ioc_value.rsplit(":", 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        ip, port_str = parts
                        port = int(port_str)
                results.append({
                    "ioc_type": "ip", "value": ip, "port": port,
                    "threat_name": threat, "first_seen": first_seen,
                })
            elif ioc_type == "domain":
                results.append({
                    "ioc_type": "domain", "value": ioc_value.lower(),
                    "threat_name": threat, "first_seen": first_seen,
                })
            elif ioc_type == "url":
                results.append({
                    "ioc_type": "url", "value": ioc_value,
                    "threat_name": threat, "first_seen": first_seen,
                })
        return results


class URLHausSource(IOCSource):
    """abuse.ch URLHaus - malicious URLs.

    API: POST https://urlhaus-api.abuse.ch/v1/payloads/
    Body: query=get_payloads (recent payloads)
    Returns URL + optional sha256 for each entry.
    """

    name = "URLHaus"
    API_URL = "https://urlhaus-api.abuse.ch/v1/payloads/"

    def __init__(self, user_agent: str = DEFAULT_USER_AGENT, timeout: float = 30.0) -> None:
        self.user_agent = user_agent
        self.timeout = timeout

    def fetch(self, limit: int = 1000) -> List[Dict[str, Any]]:
        body = urllib.parse.urlencode({"query": "get_payloads"}).encode("utf-8")
        req = urllib.request.Request(
            self.API_URL,
            data=body,
            method="POST",
            headers={
                "User-Agent": self.user_agent,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))

        if payload.get("query_status") != "OK":
            raise RuntimeError(
                f"URLHaus query failed: {payload.get('query_status', 'unknown')}"
            )

        payloads = payload.get("payloads", [])
        if not isinstance(payloads, list):
            return []

        results: List[Dict[str, Any]] = []
        for entry in payloads[:limit]:
            url = entry.get("url", "")
            if not url:
                continue
            threat = entry.get("signature", "Unknown")
            first_seen = entry.get("firstseen", "")
            results.append({
                "ioc_type": "url", "value": url,
                "threat_name": threat, "first_seen": first_seen,
            })
            sha = entry.get("sha256", "")
            if sha and len(sha) == 64:
                results.append({
                    "ioc_type": "hash", "value": sha.lower(),
                    "threat_name": threat, "first_seen": first_seen,
                })
        return results


class FeodoTrackerSource(IOCSource):
    """abuse.ch Feodo Tracker - botnet C2 IP addresses.

    API: GET https://feodotracker.abuse.ch/downloads/ipblocklist.json
    Returns a JSON array of {"ip": "...", "port": ..., "malware": "..."}.
    """

    name = "FeodoTracker"
    API_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    def __init__(self, user_agent: str = DEFAULT_USER_AGENT, timeout: float = 30.0) -> None:
        self.user_agent = user_agent
        self.timeout = timeout

    def fetch(self, limit: int = 1000) -> List[Dict[str, Any]]:
        req = urllib.request.Request(
            self.API_URL,
            headers={"User-Agent": self.user_agent, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))

        if not isinstance(payload, list):
            return []

        results: List[Dict[str, Any]] = []
        for entry in payload[:limit]:
            ip = entry.get("ip", "")
            if not ip:
                continue
            port = entry.get("port")
            if isinstance(port, str) and port.isdigit():
                port = int(port)
            elif not isinstance(port, int):
                port = None
            threat = entry.get("malware", "Unknown")
            first_seen = entry.get("first_seen", "")
            results.append({
                "ioc_type": "ip", "value": ip, "port": port,
                "threat_name": threat, "first_seen": first_seen,
            })
        return results


class IOCDownloader:
    """Downloads IOCs from a :class:`IOCSource` and stores them in SQLite."""

    COMPONENT = "ioc_feed"

    def __init__(
        self,
        db: Database,
        source: Optional[IOCSource] = None,
    ) -> None:
        self._db = db
        self.source = source or ThreatFoxSource()

    def download_and_merge(self, limit: int = 1000) -> IOCDownloadResult:
        """Fetch IOCs from the source and insert into the appropriate tables."""
        timestamp = _utcnow()
        result = IOCDownloadResult(
            success=False, source=self.source.name, timestamp=timestamp,
        )

        try:
            fetched = self.source.fetch(limit=limit)
        except Exception as exc:
            result.errors.append(f"fetch error: {exc}")
            result.status = "FETCH_ERROR"
            self._record_history(result, status="FAILED_FETCH")
            logger.exception("IOC fetch failed")
            return result

        result.iocs_fetched = len(fetched)
        if result.iocs_fetched == 0:
            result.status = "NO_IOCS"
            self._record_history(result, status="NO_IOCS")
            return result

        by_type: Dict[str, int] = {"hash": 0, "ip": 0, "domain": 0, "url": 0}
        added = 0
        duplicate = 0

        for ioc in fetched:
            ioc_type = ioc.get("ioc_type", "")
            value = ioc.get("value", "")
            if not value:
                continue
            try:
                if ioc_type == "hash":
                    cur = self._db.execute(
                        "INSERT OR IGNORE INTO ioc_hashes (sha256, source, threat_name, first_seen, added_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (value, self.source.name, ioc.get("threat_name"),
                         ioc.get("first_seen"), timestamp),
                    )
                elif ioc_type == "ip":
                    cur = self._db.execute(
                        "INSERT OR IGNORE INTO ioc_ips (ip_address, port, source, threat_name, first_seen, added_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (value, ioc.get("port"), self.source.name,
                         ioc.get("threat_name"), ioc.get("first_seen"), timestamp),
                    )
                elif ioc_type == "domain":
                    cur = self._db.execute(
                        "INSERT OR IGNORE INTO ioc_domains (domain, source, threat_name, first_seen, added_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (value, self.source.name, ioc.get("threat_name"),
                         ioc.get("first_seen"), timestamp),
                    )
                elif ioc_type == "url":
                    cur = self._db.execute(
                        "INSERT OR IGNORE INTO ioc_urls (url, source, threat_name, first_seen, added_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (value, self.source.name, ioc.get("threat_name"),
                         ioc.get("first_seen"), timestamp),
                    )
                else:
                    continue
                if cur.rowcount > 0:
                    added += 1
                    by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
                else:
                    duplicate += 1
            except Exception as exc:
                result.errors.append(f"insert error: {exc}")

        result.iocs_added = added
        result.iocs_duplicate = duplicate
        result.by_type = by_type
        result.success = added > 0
        result.status = "APPLIED" if added > 0 else "NO_NEW_IOCS"
        self._record_history(result, status=result.status)
        logger.info(
            "IOC download (%s): fetched=%d added=%d duplicates=%d by_type=%s",
            self.source.name, result.iocs_fetched, added, duplicate, by_type,
        )
        return result

    def count_all(self) -> Dict[str, int]:
        """Return counts per IOC type."""
        out = {}
        for table in ("ioc_hashes", "ioc_ips", "ioc_domains", "ioc_urls"):
            row = self._db.fetchone(f"SELECT COUNT(*) AS c FROM {table}")
            out[table] = int(row["c"]) if row else 0
        return out

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        row = self._db.fetchone(
            "SELECT * FROM ioc_ips WHERE ip_address=?", (ip,)
        )
        return dict(row) if row else None

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        row = self._db.fetchone(
            "SELECT * FROM ioc_domains WHERE domain=?", (domain.lower(),)
        )
        return dict(row) if row else None

    def lookup_hash(self, sha256: str) -> Optional[Dict]:
        row = self._db.fetchone(
            "SELECT * FROM ioc_hashes WHERE sha256=?", (sha256.lower(),)
        )
        return dict(row) if row else None

    def clear_source(self, source_name: str) -> int:
        """Remove all IOCs from a specific source. Returns total removed."""
        total = 0
        for table in ("ioc_hashes", "ioc_ips", "ioc_domains", "ioc_urls"):
            cur = self._db.execute(
                f"DELETE FROM {table} WHERE source=?", (source_name,)
            )
            total += cur.rowcount
        return total

    def _record_history(self, result: IOCDownloadResult, status: str) -> None:
        try:
            details = (
                f"source={result.source}, fetched={result.iocs_fetched}, "
                f"added={result.iocs_added}, duplicates={result.iocs_duplicate}, "
                f"by_type={result.by_type}"
            )
            if result.errors:
                details += f", errors={result.errors[:3]}"
            self._db.execute(
                "INSERT INTO update_history (applied_at, component, from_version, to_version, status, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (result.timestamp, self.COMPONENT, None, None, status, details),
            )
        except Exception:
            logger.exception("Could not record IOC download history")


IOC_SOURCES: Dict[str, type] = {
    "threatfox": ThreatFoxSource,
    "urlhaus": URLHausSource,
    "feodo": FeodoTrackerSource,
}


def get_ioc_source(key: str) -> IOCSource:
    """Construct an IOC source by key. Raises KeyError on unknown key."""
    cls = IOC_SOURCES.get(key.lower())
    if cls is None:
        raise KeyError(
            f"Unknown IOC source: {key!r}. Available: {list(IOC_SOURCES.keys())}"
        )
    return cls()
