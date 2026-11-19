"""Schema migrations for ITShield SQLite database.

Section 12 lists every planned table for the full project. In this version
we create only the tables already in use:

    * scan_jobs        - one row per scan execution
    * scan_results     - one row per scanned file
    * scan_stats       - aggregate stats for a scan job
    * signatures       - cached signature bank rows (future)
    * audit_logs       - security-relevant operations (future, schema only)

Other tables from the architecture document (process_events, file_events,
network_events, ...) are declared here as empty placeholders so the schema
is forward-compatible. They will be filled in once their collectors are
implemented.
"""

from __future__ import annotations

from itshield.logging.logger import get_logger
from itshield.storage.database import Database

logger = get_logger(__name__)

_SCHEMA = """
-- =========================================================
-- scan_jobs: one row per scan execution
-- =========================================================
CREATE TABLE IF NOT EXISTS scan_jobs (
    id            TEXT PRIMARY KEY,
    target_path   TEXT NOT NULL,
    state         TEXT NOT NULL,        -- PENDING / RUNNING / PAUSED / CANCELLED / FAILED / COMPLETED
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    files_total   INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    files_malicious INTEGER DEFAULT 0,
    files_suspicious INTEGER DEFAULT 0,
    files_clean   INTEGER DEFAULT 0,
    files_unknown INTEGER DEFAULT 0,
    files_skipped INTEGER DEFAULT 0,
    error         TEXT
);

-- =========================================================
-- scan_results: one row per scanned file
-- =========================================================
CREATE TABLE IF NOT EXISTS scan_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id        TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    file_size     INTEGER,
    file_type     TEXT,
    sha256        TEXT,
    detection     TEXT,                  -- CLEAN / UNKNOWN / SUSPICIOUS / MALICIOUS / SKIPPED
    matched_rules TEXT,                  -- comma-separated YARA rule names
    reason        TEXT,
    scanned_at    TEXT NOT NULL,
    FOREIGN KEY(job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scan_results_job ON scan_results(job_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_sha256 ON scan_results(sha256);

-- =========================================================
-- signatures: cached entries from the signature bank
-- =========================================================
CREATE TABLE IF NOT EXISTS signatures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT UNIQUE NOT NULL,
    name         TEXT,
    family       TEXT,
    severity     TEXT,
    source       TEXT,
    added_at     TEXT NOT NULL
);

-- =========================================================
-- audit_logs: every security-relevant action
-- =========================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    actor      TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    details    TEXT
);

-- =========================================================
-- Placeholder tables (declared for forward compatibility;
-- collectors not implemented yet).
-- =========================================================
CREATE TABLE IF NOT EXISTS system_info (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at TEXT NOT NULL,
    sha256      TEXT,
    file_path   TEXT,
    detection   TEXT,
    severity    TEXT,
    details     TEXT
);

CREATE TABLE IF NOT EXISTS quarantine (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    quarantined_at TEXT NOT NULL,
    original_path TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size         INTEGER,
    metadata     TEXT
);

CREATE TABLE IF NOT EXISTS process_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    process_id      INTEGER,
    process_name    TEXT,
    parent_process_id INTEGER,
    event_type      TEXT,
    metadata        TEXT
);

CREATE TABLE IF NOT EXISTS file_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    path      TEXT,
    event_type TEXT,
    metadata  TEXT
);

CREATE TABLE IF NOT EXISTS network_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    protocol  TEXT,
    local_addr  TEXT,
    remote_addr TEXT,
    remote_port INTEGER,
    process_id INTEGER,
    state     TEXT,
    metadata  TEXT
);

CREATE TABLE IF NOT EXISTS dns_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    query     TEXT,
    query_type TEXT,
    process_id INTEGER,
    answers   TEXT,
    metadata  TEXT
);

CREATE TABLE IF NOT EXISTS security_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity  TEXT,
    category  TEXT,
    title     TEXT,
    details   TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id         TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    severity   TEXT,
    state      TEXT,
    summary    TEXT
);

CREATE TABLE IF NOT EXISTS incident_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    added_at    TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS yara_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT UNIQUE NOT NULL,
    rule_text  TEXT NOT NULL,
    enabled    INTEGER DEFAULT 1,
    added_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exclusions (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    path  TEXT,
    hash  TEXT,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS update_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    applied_at  TEXT NOT NULL,
    component   TEXT,
    from_version TEXT,
    to_version  TEXT,
    status      TEXT,
    details     TEXT
);

-- =========================================================
-- Phase 12: IOC tables (Indicators of Compromise from
-- external threat-intel feeds: ThreatFox, URLHaus, Feodo).
-- =========================================================
CREATE TABLE IF NOT EXISTS ioc_hashes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT NOT NULL,
    source       TEXT NOT NULL,
    threat_name  TEXT,
    first_seen   TEXT,
    added_at     TEXT NOT NULL,
    UNIQUE(sha256, source)
);
CREATE INDEX IF NOT EXISTS idx_ioc_hashes_sha256 ON ioc_hashes(sha256);

CREATE TABLE IF NOT EXISTS ioc_ips (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address   TEXT NOT NULL,
    port         INTEGER,
    source       TEXT NOT NULL,
    threat_name  TEXT,
    first_seen   TEXT,
    added_at     TEXT NOT NULL,
    UNIQUE(ip_address, port, source)
);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_ip ON ioc_ips(ip_address);

CREATE TABLE IF NOT EXISTS ioc_domains (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    source       TEXT NOT NULL,
    threat_name  TEXT,
    first_seen   TEXT,
    added_at     TEXT NOT NULL,
    UNIQUE(domain, source)
);
CREATE INDEX IF NOT EXISTS idx_ioc_domains_domain ON ioc_domains(domain);

CREATE TABLE IF NOT EXISTS ioc_urls (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    url          TEXT NOT NULL,
    source       TEXT NOT NULL,
    threat_name  TEXT,
    first_seen   TEXT,
    added_at     TEXT NOT NULL,
    UNIQUE(url, source)
);
"""


def run_migrations(db: Database) -> None:
    """Apply the schema. Idempotent: safe to call on every startup."""
    logger.info("Running SQLite migrations on %s", db.path)
    db.executescript(_SCHEMA)
    logger.info("Migrations applied successfully")
