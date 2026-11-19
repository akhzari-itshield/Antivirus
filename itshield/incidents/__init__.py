"""Incident management package for ITShield (Phase 7).

An *incident* is a security-relevant event (or chain of events) that
requires investigation. The Correlation Engine and Behavior Analyzer
both create incidents when they detect suspicious patterns.

This package owns the lifecycle of incidents:
    * creation (with linked events)
    * state transitions (OPEN -> INVESTIGATING -> RESOLVED / DISMISSED)
    * persistence in the ``incidents`` + ``incident_events`` tables
"""

from itshield.incidents.manager import (
    IncidentManager,
    Incident,
    IncidentState,
    IncidentSeverity,
)

__all__ = [
    "IncidentManager",
    "Incident",
    "IncidentState",
    "IncidentSeverity",
]
