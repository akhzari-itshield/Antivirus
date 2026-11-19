"""Unit tests for Phase 12: YaraSourceRegistry + IOCDownloader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.update.yara_sources import (
    YaraSource, YARA_SOURCES, get_source, list_sources, sources_summary,
)
from itshield.update.ioc_downloader import (
    IOCSource, IOCDownloader, IOCDownloadResult,
    ThreatFoxSource, URLHausSource, FeodoTrackerSource,
    IOC_SOURCES, get_ioc_source,
)


@pytest.fixture
def db(tmp_project: Path) -> Database:
    database = Database(tmp_project / "data" / "p12.db")
    run_migrations(database)
    yield database
    database.close()


def test_registry_has_12_sources() -> None:
    assert len(YARA_SOURCES) == 12


def test_registry_includes_key_sources() -> None:
    keys = {s.key for s in YARA_SOURCES}
    expected = {
        "neo23x0", "elastic", "reversinglabs", "inquest",
        "bartblaze", "deadbits", "didierstevens", "strangereal",
        "jeff0falltrades", "yaraforge", "eset", "mcafee",
    }
    assert expected.issubset(keys), f"Missing: {expected - keys}"


def test_get_source_returns_object() -> None:
    src = get_source("elastic")
    assert src is not None
    assert src.repo == "elastic/protections-artifacts"
    assert src.ref == "main"


def test_get_source_unknown_returns_none() -> None:
    assert get_source("nonexistent") is None


def test_list_sources_returns_all() -> None:
    sources = list_sources()
    assert len(sources) == 12
    assert all(isinstance(s, YaraSource) for s in sources)


def test_sources_summary_is_json_serializable() -> None:
    summary = sources_summary()
    assert len(summary) == 12
    json.dumps(summary)
    for entry in summary:
        assert "key" in entry
        assert "repo" in entry
        assert "prefix" in entry
        assert "subdirs" in entry


def test_every_source_has_unique_prefix() -> None:
    """No two sources should produce the same prefix (would cause file collisions)."""
    prefixes = {s.effective_prefix for s in YARA_SOURCES}
    assert len(prefixes) == len(YARA_SOURCES)


def test_every_source_has_repo_and_description() -> None:
    for s in YARA_SOURCES:
        assert s.repo, f"{s.key} missing repo"
        assert "/" in s.repo, f"{s.key} repo not in owner/name form"
        assert s.description, f"{s.key} missing description"


def test_neo23x0_is_default_and_backwards_compatible() -> None:
    src = get_source("neo23x0")
    assert src is not None
    assert src.repo == "neo23x0/signature-base"
    assert src.ref == "master"
    assert "yara" in src.subdirs


class _StubIOCSource(IOCSource):
    """Returns a fixed list of IOCs for deterministic tests."""

    name = "TestIOCSource"

    def __init__(self, iocs: List[Dict[str, Any]]) -> None:
        self._iocs = iocs

    def fetch(self, limit: int = 1000) -> List[Dict[str, Any]]:
        return self._iocs[:limit]


def _make_hash_ioc(sha: str, threat: str = "TestThreat") -> Dict[str, Any]:
    return {"ioc_type": "hash", "value": sha.lower(), "threat_name": threat,
            "first_seen": "2026-01-01T00:00:00Z"}


def _make_ip_ioc(ip: str, port: int = 443, threat: str = "BotnetC2") -> Dict[str, Any]:
    return {"ioc_type": "ip", "value": ip, "port": port, "threat_name": threat,
            "first_seen": "2026-01-01T00:00:00Z"}


def _make_domain_ioc(domain: str, threat: str = "Phishing") -> Dict[str, Any]:
    return {"ioc_type": "domain", "value": domain.lower(), "threat_name": threat,
            "first_seen": "2026-01-01T00:00:00Z"}


def _make_url_ioc(url: str, threat: str = "MalwareDrop") -> Dict[str, Any]:
    return {"ioc_type": "url", "value": url, "threat_name": threat,
            "first_seen": "2026-01-01T00:00:00Z"}


def test_ioc_downloader_merges_all_types(db: Database) -> None:
    source = _StubIOCSource([
        _make_hash_ioc("a" * 64),
        _make_ip_ioc("1.2.3.4"),
        _make_domain_ioc("evil.example.com"),
        _make_url_ioc("http://evil.example.com/payload"),
    ])
    dl = IOCDownloader(db=db, source=source)
    result = dl.download_and_merge()
    assert result.success
    assert result.iocs_fetched == 4
    assert result.iocs_added == 4
    assert result.by_type == {"hash": 1, "ip": 1, "domain": 1, "url": 1}

    assert db.fetchone("SELECT * FROM ioc_hashes WHERE sha256=?", ("a" * 64,))
    assert db.fetchone("SELECT * FROM ioc_ips WHERE ip_address=?", ("1.2.3.4",))
    assert db.fetchone("SELECT * FROM ioc_domains WHERE domain=?", ("evil.example.com",))
    assert db.fetchone("SELECT * FROM ioc_urls WHERE url=?", ("http://evil.example.com/payload",))


def test_ioc_downloader_skips_duplicates(db: Database) -> None:
    source = _StubIOCSource([_make_hash_ioc("b" * 64)])
    dl = IOCDownloader(db=db, source=source)
    r1 = dl.download_and_merge()
    assert r1.iocs_added == 1
    r2 = dl.download_and_merge()
    assert r2.iocs_added == 0
    assert r2.iocs_duplicate == 1
    assert r2.status == "NO_NEW_IOCS"


def test_ioc_downloader_lookup_methods(db: Database) -> None:
    source = _StubIOCSource([
        _make_hash_ioc("c" * 64, "TrojanX"),
        _make_ip_ioc("5.6.7.8", 443, "C2Server"),
        _make_domain_ioc("bad.example.org", "PhishingKit"),
    ])
    dl = IOCDownloader(db=db, source=source)
    dl.download_and_merge()

    h = dl.lookup_hash("c" * 64)
    assert h is not None
    assert h["threat_name"] == "TrojanX"
    assert dl.lookup_hash("C" * 64) is not None

    ip = dl.lookup_ip("5.6.7.8")
    assert ip is not None
    assert ip["port"] == 443
    assert ip["threat_name"] == "C2Server"

    d = dl.lookup_domain("bad.example.org")
    assert d is not None
    assert d["threat_name"] == "PhishingKit"
    assert dl.lookup_domain("BAD.EXAMPLE.ORG") is not None

    assert dl.lookup_ip("10.0.0.1") is None
    assert dl.lookup_hash("0" * 64) is None


def test_ioc_downloader_count_all(db: Database) -> None:
    source = _StubIOCSource([
        _make_hash_ioc("d" * 64),
        _make_hash_ioc("e" * 64),
        _make_ip_ioc("9.9.9.9"),
    ])
    dl = IOCDownloader(db=db, source=source)
    dl.download_and_merge()
    counts = dl.count_all()
    assert counts["ioc_hashes"] == 2
    assert counts["ioc_ips"] == 1
    assert counts["ioc_domains"] == 0
    assert counts["ioc_urls"] == 0


def test_ioc_downloader_clear_source(db: Database) -> None:
    source1 = _StubIOCSource([_make_hash_ioc("f" * 64)])
    source2 = _StubIOCSource([_make_hash_ioc("g" * 64)])
    source1.name = "SourceA"
    source2.name = "SourceB"
    IOCDownloader(db=db, source=source1).download_and_merge()
    IOCDownloader(db=db, source=source2).download_and_merge()

    dl = IOCDownloader(db=db, source=source1)
    removed = dl.clear_source("SourceA")
    assert removed == 1
    assert db.fetchone("SELECT * FROM ioc_hashes WHERE sha256=?", ("g" * 64,))
    assert not db.fetchone("SELECT * FROM ioc_hashes WHERE sha256=?", ("f" * 64,))


def test_ioc_downloader_handles_fetch_error(db: Database) -> None:
    class _FailingSource(IOCSource):
        name = "Failing"
        def fetch(self, limit: int = 1000):
            raise RuntimeError("network down")
    dl = IOCDownloader(db=db, source=_FailingSource())
    result = dl.download_and_merge()
    assert not result.success
    assert result.status == "FETCH_ERROR"


def test_ioc_downloader_records_history(db: Database) -> None:
    source = _StubIOCSource([_make_hash_ioc("h" * 64)])
    IOCDownloader(db=db, source=source).download_and_merge()
    rows = db.fetchall(
        "SELECT component, status FROM update_history "
        "WHERE component='ioc_feed'"
    )
    assert len(rows) == 1
    assert rows[0]["status"] == "APPLIED"


def test_ioc_source_registry_has_three_sources() -> None:
    assert len(IOC_SOURCES) == 3
    assert "threatfox" in IOC_SOURCES
    assert "urlhaus" in IOC_SOURCES
    assert "feodo" in IOC_SOURCES


def test_get_ioc_source_constructs_instances() -> None:
    tf = get_ioc_source("threatfox")
    uh = get_ioc_source("urlhaus")
    fe = get_ioc_source("feodo")
    assert isinstance(tf, ThreatFoxSource)
    assert isinstance(uh, URLHausSource)
    assert isinstance(fe, FeodoTrackerSource)
    assert tf.name == "ThreatFox"
    assert uh.name == "URLHaus"
    assert fe.name == "FeodoTracker"


def test_get_ioc_source_unknown_raises() -> None:
    with pytest.raises(KeyError, match="Unknown IOC source"):
        get_ioc_source("nonexistent")


def test_threatfox_api_url() -> None:
    src = ThreatFoxSource()
    assert "threatfox-api.abuse.ch" in src.API_URL


def test_urlhaus_api_url() -> None:
    src = URLHausSource()
    assert "urlhaus-api.abuse.ch" in src.API_URL


def test_feodo_api_url() -> None:
    src = FeodoTrackerSource()
    assert "feodotracker.abuse.ch" in src.API_URL
