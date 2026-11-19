"""Incident Manager - persistence and lifecycle for security incidents.

Backed by the ``incidents`` and ``incident_events`` tables created in
:mod:`itshield.storage.migrations`.

Phase 7 of the architecture document (sections 10 and 16). The
Correlation Engine and Behavior Analyzer call into this manager whenever
they detect a suspicious chain of events; the manager records the
incident, links the contributing events, and lets the user (via the
GUI) investigate, resolve, or dismiss it.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from itshield.logging.logger import get_logger
from itshield.storage.database import Database

logger = get_logger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class IncidentState(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Incident:
    """One security incident record."""

    id: str
    created_at: str
    severity: IncidentSeverity
    state: IncidentState
    title: str
    summary: str
    rule_name: str = ""
    linked_event_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["state"] = self.state.value
        return d


class IncidentManager:
    """CRUD + lifecycle operations for incidents."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def create(
        self,
        title: str,
        summary: str,
        severity: IncidentSeverity,
        rule_name: str = "",
        linked_event_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Incident:
        """Insert a new OPEN incident and return it."""
        incident_id = str(uuid.uuid4())
        now = _utcnow()

        packed_summary = f"{title}\n\n{summary}"

        self._db.execute(
            """
            INSERT INTO incidents
                (id, created_at, severity, state, summary)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                now,
                severity.value,
                IncidentState.OPEN.value,
                packed_summary,
            ),
        )

        for event_id in (linked_event_ids or []):
            self._db.execute(
                """
                INSERT INTO incident_events (incident_id, event_id, added_at)
                VALUES (?, ?, ?)
                """,
                (incident_id, event_id, _utcnow()),
            )

        incident = Incident(
            id=incident_id,
            created_at=now,
            severity=severity,
            state=IncidentState.OPEN,
            title=title,
            summary=summary,
            rule_name=rule_name,
            linked_event_ids=list(linked_event_ids or []),
            metadata=metadata or {},
        )

        logger.info(
            "Created incident %s severity=%s rule=%s linked_events=%d",
            incident_id[:8], severity.value, rule_name, len(incident.linked_event_ids),
        )
        return incident

    def transition(self, incident_id: str, new_state: IncidentState) -> bool:
        cur = self._db.execute(
            "UPDATE incidents SET state=? WHERE id=?",
            (new_state.value, incident_id),
        )
        return cur.rowcount > 0

    def resolve(self, incident_id: str) -> bool:
        return self.transition(incident_id, IncidentState.RESOLVED)

    def dismiss(self, incident_id: str) -> bool:
        return self.transition(incident_id, IncidentState.DISMISSED)

    def start_investigating(self, incident_id: str) -> bool:
        return self.transition(incident_id, IncidentState.INVESTIGATING)

    def list_incidents(
        self,
        state_filter: Optional[IncidentState] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if state_filter is None:
            rows = self._db.fetchall(
                "SELECT id, created_at, severity, state, summary "
                "FROM incidents ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        else:
            rows = self._db.fetchall(
                "SELECT id, created_at, severity, state, summary "
                "FROM incidents WHERE state=? ORDER BY created_at DESC LIMIT ?",
                (state_filter.value, limit),
            )
        result = []
        for r in rows:
            item = dict(r)
            parts = (item.get("summary") or "").split("\n\n", 1)
            item["title"] = parts[0] if parts else ""
            item["summary"] = parts[1] if len(parts) > 1 else ""
            linked = self._db.fetchall(
                "SELECT event_id FROM incident_events WHERE incident_id=?",
                (item["id"],),
            )
            item["linked_event_ids"] = [r2["event_id"] for r2 in linked]
            result.append(item)
        return result

    def get(self, incident_id: str) -> Optional[Dict[str, Any]]:
        row = self._db.fetchone(
            "SELECT id, created_at, severity, state, summary "
            "FROM incidents WHERE id=?",
            (incident_id,),
        )
        if not row:
            return None
        item = dict(row)
        parts = (item.get("summary") or "").split("\n\n", 1)
        item["title"] = parts[0] if parts else ""
        item["summary"] = parts[1] if len(parts) > 1 else ""
        linked = self._db.fetchall(
            "SELECT event_id, added_at FROM incident_events WHERE incident_id=?",
            (item["id"],),
        )
        item["linked_events"] = [dict(r) for r in linked]
        return item

    def count_by_state(self) -> Dict[str, int]:
        rows = self._db.fetchall(
            "SELECT state, COUNT(*) AS c FROM incidents GROUP BY state"
        )
        return {r["state"]: int(r["c"]) for r in rows}
