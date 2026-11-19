"""Reporting package for ITShield (Phase 10).

Generates human-readable and machine-readable reports from scan jobs
stored in the SQLite database:

    * :class:`ReportGenerator` - builds reports in HTML, JSON and plain text.
    * Reports are saved to ``reports/`` (see :mod:`itshield.config.settings`).

Report sections:
    * Header with timestamp and target path
    * Summary card (files total/scanned/clean/suspicious/malicious/skipped)
    * Per-file results table (sortable, color-coded verdicts in HTML)
    * Threats detail section (only MALICIOUS + SUSPICIOUS files)
    * Footer with job id, duration and ITShield version
"""

from itshield.reporting.report_generator import (
    ReportGenerator,
    ReportFormat,
    ScanReport,
)

__all__ = ["ReportGenerator", "ReportFormat", "ScanReport"]
