"""IOC Matcher - checks events against the IOC database (Phase 13).

Section 17 of the architecture document - "Network Monitoring" combined
with Section 16 - "Behavioral Analysis".

The matcher subscribes to the EventBus and checks every relevant event
against the IOC tables populated by :class:`~itshield.update.ioc_downloader.IOCDownloader`:

    * NETWORK_CONNECTION events  -> checked against ``ioc_ips``
      (matches the remote_addr field of the event metadata)
    * THREAT_DETECTED events with file_hash -> checked against ``ioc_hashes``
      (corroborates a signature match with external threat intel)
    * Any event with metadata["domain"] -> checked against ``ioc_domains``
    * Any event with metadata["url"]    -> checked against ``ioc_urls``

When a match is found, a ``SECURITY_ALERT`` event is published with
severity HIGH (for IP/domain matches) or CRITICAL (for hash matches,
since those indicate a known-malicious file). The original event id is
carried in metadata so the Correlation Engine can chain them.

The matcher is intentionally read-only against the IOC tables: it never
writes to them, so the IOC DB is purely fed by the downloader.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger
from itshield.storage.database import Database

logger = get_logger(__name__)


class IOCMatcher:
    """Subscribes to events and checks them against the IOC database.

    Implements the Core's ModuleProtocol informally (start/stop/health).
    """

    name = "ioc_matcher"
    dependencies: tuple[str, ...] = ("event_bus", "storage")

    def __init__(
        self,
        bus: EventBus,
        db: Database,
    ) -> None:
        self._bus = bus
        self._db = db
        self._unsubscribe: Optional[Callable[[], None]] = None
        self._lock = threading.RLock()
        self._events_checked = 0
        self._matches_found = 0

    def start(self) -> None:
        self._unsubscribe = self._bus.subscribe(self._on_event)
        logger.info("IOCMatcher started")

    def stop(self) -> None:
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        logger.info(
            "IOCMatcher stopped (events_checked=%d, matches=%d)",
            self._events_processed(), self._matches_found,
        )

    def health(self) -> dict:
        with self._lock:
            return {
                "running": self._unsubscribe is not None,
                "events_checked": self._events_checked,
                "matches_found": self._matches_found,
            }

    def _events_processed(self) -> int:
        return self._events_checked

    def _on_event(self, event: Event) -> None:
        with self._lock:
            self._events_checked += 1

        if event.event_type == EventType.NETWORK_CONNECTION:
            remote = event.metadata.get("remote_addr", "")
            if remote:
                self._check_ip(remote, event)

        if event.event_type == EventType.THREAT_DETECTED:
            sha = event.file_hash or event.metadata.get("sha256")
            if sha:
                self._check_hash(sha, event)

        domain = event.metadata.get("domain")
        if domain:
            self._check_domain(domain, event)

        url = event.metadata.get("url")
        if url:
            self._check_url(url, event)

    def _check_ip(self, ip: str, event: Event) -> None:
        row = self._db.fetchone(
            "SELECT threat_name, source FROM ioc_ips WHERE ip_address=?",
            (ip,),
        )
        if row is None:
            return
        self._matches_found += 1
        threat = row["threat_name"] or "Unknown"
        src = row["source"]
        logger.warning(
            "IOC IP match: %s (threat=%s, source=%s) on event %s",
            ip, threat, src, event.event_id,
        )
        self._bus.publish(Event(
            event_type=EventType.SECURITY_ALERT,
            source=self.name,
            severity=Severity.ERROR,
            process_id=event.process_id,
            process_name=event.process_name,
            metadata={
                "ioc_type": "ip",
                "ioc_value": ip,
                "threat_name": threat,
                "ioc_source": src,
                "matched_event_id": event.event_id,
                "matched_event_type": event.event_type.value,
            },
        ))

    def _check_hash(self, sha256: str, event: Event) -> None:
        row = self._db.fetchone(
            "SELECT threat_name, source FROM ioc_hashes WHERE sha256=?",
            (sha256.lower(),),
        )
        if row is None:
            return
        self._matches_found += 1
        threat = row["threat_name"] or "Unknown"
        src = row["source"]
        logger.warning(
            "IOC hash match: %s (threat=%s, source=%s) on event %s",
            sha256[:12], threat, src, event.event_id,
        )
        self._bus.publish(Event(
            event_type=EventType.SECURITY_ALERT,
            source=self.name,
            severity=Severity.CRITICAL,
            file_path=event.file_path,
            file_hash=sha256,
            metadata={
                "ioc_type": "hash",
                "ioc_value": sha256,
                "threat_name": threat,
                "ioc_source": src,
                "matched_event_id": event.event_id,
                "matched_event_type": event.event_type.value,
            },
        ))

    def _check_domain(self, domain: str, event: Event) -> None:
        row = self._db.fetchone(
            "SELECT threat_name, source FROM ioc_domains WHERE domain=?",
            (domain.lower(),),
        )
        if row is None:
            return
        self._matches_found += 1
        threat = row["threat_name"] or "Unknown"
        src = row["source"]
        logger.warning(
            "IOC domain match: %s (threat=%s, source=%s) on event %s",
            domain, threat, src, event.event_id,
        )
        self._bus.publish(Event(
            event_type=EventType.SECURITY_ALERT,
            source=self.name,
            severity=Severity.ERROR,
            metadata={
                "ioc_type": "domain",
                "ioc_value": domain,
                "threat_name": threat,
                "ioc_source": src,
                "matched_event_id": event.event_id,
                "matched_event_type": event.event_type.value,
            },
        ))

    def _check_url(self, url: str, event: Event) -> None:
        row = self._db.fetchone(
            "SELECT threat_name, source FROM ioc_urls WHERE url=?",
            (url,),
        )
        if row is None:
            return
        self._matches_found += 1
        threat = row["threat_name"] or "Unknown"
        src = row["source"]
        logger.warning(
            "IOC URL match: %s (threat=%s, source=%s) on event %s",
            url[:50], threat, src, event.event_id,
        )
        self._bus.publish(Event(
            event_type=EventType.SECURITY_ALERT,
            source=self.name,
            severity=Severity.ERROR,
            metadata={
                "ioc_type": "url",
                "ioc_value": url,
                "threat_name": threat,
                "ioc_source": src,
                "matched_event_id": event.event_id,
                "matched_event_type": event.event_type.value,
            },
        ))
