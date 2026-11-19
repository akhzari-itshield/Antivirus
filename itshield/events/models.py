"""Event models for ITShield.

The set of event types matches section 8.2 of the architecture document.
Real collectors are not yet wired up; the model is the foundation that the
Event Bus, IPC handlers and future Process/Network monitors will publish to.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class EventType(str, Enum):
    """Enumeration of every event type the ITShield pipeline understands."""

    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_DELETED = "FILE_DELETED"
    PROCESS_CREATED = "PROCESS_CREATED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_QUERY = "DNS_QUERY"
    THREAT_DETECTED = "THREAT_DETECTED"
    SECURITY_ALERT = "SECURITY_ALERT"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_PROGRESS = "SCAN_PROGRESS"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_CANCELLED = "SCAN_CANCELLED"


class Severity(str, Enum):
    """Severity buckets for events and alerts."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def _utcnow_iso() -> str:
    """Return current UTC time in ISO-8601 with a trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class Event:
    """A single normalized event flowing through the pipeline.

    The shape mirrors the example JSON in section 8.3 of the document.
    ``metadata`` is intentionally free-form so collectors can attach
    format-specific payloads (PE sections, DNS answers, scan stats, ...).
    """

    event_type: EventType
    source: str
    severity: Severity = Severity.INFO
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_utcnow_iso)
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable representation."""
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Reconstruct an Event from a dict (round-trip with to_dict)."""
        data = dict(data)
        if "event_type" in data:
            data["event_type"] = EventType(data["event_type"])
        if "severity" in data:
            data["severity"] = Severity(data["severity"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
