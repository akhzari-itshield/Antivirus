"""Unit tests for Phase 9: HTTPUpdateSource, YaraRuleDownloader, YaraEngine dir loading."""

from __future__ import annotations

import io
import json
import os
import socket
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from itshield.scanner.yara_engine import YaraEngine
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.update.http_source import HTTPUpdateSource, GitHubArchiveSource
from itshield.update.yara_downloader import (
    YaraRuleDownloader, DEFAULT_REPO,
)


@pytest.fixture
def db(tmp_project: Path) -> Database:
    database = Database(tmp_project / "data" / "p9.db")
    run_migrations(database)
    yield database
    database.close()


@pytest.fixture
def rules_dir(tmp_project: Path) -> Path:
    """A clean rules directory (separate from the conftest one)."""
    d = tmp_project / "rules_test"
    d.mkdir(exist_ok=True)
    return d


class _MockHTTPHandler(BaseHTTPRequestHandler):
    """Serves a fixed bytes payload at /payload and 404 elsewhere."""

    payload: bytes = b""  # set per-test via class attribute

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler convention
        if self.path == "/payload":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.payload)))
            self.end_headers()
            self.wfile.write(self.payload)
        elif self.path == "/missing":
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(500)
            self.end_headers()

    def log_message(self, *args, **kwargs):  # silence
        pass


@pytest.fixture
def http_server(tmp_project: Path):
    """Spin up a one-shot HTTP server on a random free port."""
    payload = b"hello phase 9"
    _MockHTTPHandler.payload = payload

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = HTTPServer(("127.0.0.1", port), _MockHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}/payload", payload, f"http://127.0.0.1:{port}/missing"

    server.shutdown()
    thread.join(timeout=2.0)


def test_http_source_downloads_ok(http_server, tmp_project: Path) -> None:
    url, payload, _ = http_server
    src = HTTPUpdateSource(timeout=5.0)
    dest = tmp_project / "dl.bin"
    result = src.download(url, dest)
    assert result.success
    assert result.status == "OK"
    assert result.bytes_downloaded == len(payload)
    assert dest.read_bytes() == payload


def test_http_source_verifies_sha256(http_server, tmp_project: Path) -> None:
    import hashlib
    url, payload, _ = http_server
    src = HTTPUpdateSource(timeout=5.0)
    dest = tmp_project / "dl.bin"
    expected = hashlib.sha256(payload).hexdigest()
    result = src.download(url, dest, expected_sha256=expected)
    assert result.success
    assert result.sha256 == expected


def test_http_source_hash_mismatch(http_server, tmp_project: Path) -> None:
    url, payload, _ = http_server
    src = HTTPUpdateSource(timeout=5.0)
    dest = tmp_project / "dl.bin"
    result = src.download(url, dest, expected_sha256="0" * 64)
    assert not result.success
    assert result.status == "HASH_MISMATCH"
    assert not dest.exists()


def test_http_source_404(http_server, tmp_project: Path) -> None:
    _, _, missing_url = http_server
    src = HTTPUpdateSource(timeout=5.0)
    dest = tmp_project / "dl.bin"
    result = src.download(missing_url, dest)
    assert not result.success
    assert result.status == "HTTP_ERROR"


def test_http_source_network_error(tmp_project: Path) -> None:
    """Point at a port nothing is listening on -> NETWORK_ERROR."""
    src = HTTPUpdateSource(timeout=2.0)
    dest = tmp_project / "dl.bin"
    result = src.download("http://127.0.0.1:1/payload", dest)
    assert not result.success
    assert result.status in ("NETWORK_ERROR", "HTTP_ERROR")


def _write_yar(path: Path, rule_name: str, string: str) -> None:
    path.write_text(
        f'rule {rule_name} {{\n'
        f'    strings:\n'
        f'        $s = "{string}"\n'
        f'    condition:\n'
        f'        $s\n'
        f'}}\n'
    )


def test_yara_engine_loads_from_directory(rules_dir: Path) -> None:
    """When rules_path is a directory, load every .yar file in it."""
    _write_yar(rules_dir / "rule_a.yar", "TestRuleA", "alpha")
    _write_yar(rules_dir / "rule_b.yar", "TestRuleB", "beta")

    engine = YaraEngine(rules_path=rules_dir)
    assert engine.ready
    assert engine.rule_count >= 2

    test_file = rules_dir / "test_a.txt"
    test_file.write_text("this file contains alpha")
    matches = engine.scan_file(test_file)
    rule_names = [m.rule for m in matches]
    assert "TestRuleA" in rule_names


def test_yara_engine_reload_picks_up_new_files(rules_dir: Path) -> None:
    """reload() should recompile and pick up newly added .yar files."""
    _write_yar(rules_dir / "rule_a.yar", "TestRuleA", "alpha")
    engine = YaraEngine(rules_path=rules_dir)
    initial_count = engine.rule_count

    _write_yar(rules_dir / "rule_b.yar", "TestRuleB", "beta")
    new_count = engine.reload()
    assert new_count > initial_count


def test_yara_engine_empty_directory(rules_dir: Path) -> None:
    """An empty directory should leave the engine not ready."""
    engine = YaraEngine(rules_path=rules_dir)
    assert not engine.ready
    assert engine.rule_count == 0


def test_yara_engine_single_file_still_works(tmp_project: Path) -> None:
    """Backward-compat: passing a single .yar file path still works."""
    f = tmp_project / "single.yar"
    _write_yar(f, "SingleRule", "marker")
    engine = YaraEngine(rules_path=f)
    assert engine.ready
    assert engine.rule_count == 1


def _make_fake_signature_base_zip() -> bytes:
    """Build a ZIP that mimics the structure of neo23x0/signature-base archive.

    Layout inside the ZIP:
        signature-base-master/yara/rule_gen_1.yar
        signature-base-master/yara/rule_gen_2.yar
        signature-base-master/yara/base_index.yar     (should be skipped)
        signature-base-master/malware/rule_mal_A.yar
        signature-base-master/iocs/some_ioc.txt        (not .yar, skipped)
        signature-base-master/README.md                (not in yara/ or malware/)
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "signature-base-master/yara/rule_gen_1.yar",
            'rule Gen_Rule_One { strings: $a = "alpha" condition: $a }\n',
        )
        zf.writestr(
            "signature-base-master/yara/rule_gen_2.yar",
            'rule Gen_Rule_Two { strings: $b = "beta" condition: $b }\n',
        )
        zf.writestr(
            "signature-base-master/yara/base_index.yar",
            'include "rule_gen_1.yar"\n',
        )
        zf.writestr(
            "signature-base-master/malware/rule_mal_A.yar",
            'rule Malware_Rule_A { strings: $m = "malware" condition: $m }\n',
        )
        zf.writestr(
            "signature-base-master/iocs/some_ioc.txt",
            "this is not a YARA file\n",
        )
        zf.writestr(
            "signature-base-master/README.md",
            "# Signature Base\n",
        )
    return buf.getvalue()


class _StubGitHubSource:
    """Replaces GitHubArchiveSource so we don't hit the real GitHub."""

    def __init__(self, archive_bytes: bytes) -> None:
        self._archive_bytes = archive_bytes

    def download(self, dest_path: str | Path):
        from itshield.update.http_source import DownloadResult
        import hashlib
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self._archive_bytes)
        return DownloadResult(
            success=True,
            url="stub://fake",
            local_path=str(dest),
            bytes_downloaded=len(self._archive_bytes),
            sha256=hashlib.sha256(self._archive_bytes).hexdigest(),
            status="OK",
        )


def test_yara_downloader_merges_rules(db: Database, rules_dir: Path) -> None:
    archive_bytes = _make_fake_signature_base_zip()
    stub = _StubGitHubSource(archive_bytes)
    dl = YaraRuleDownloader(
        db=db, rules_dir=rules_dir,
        github_source=stub,  # type: ignore[arg-type]
    )
    result = dl.download_and_merge()
    assert result.success
    assert result.rules_downloaded == 3
    assert result.rules_skipped == 1  # base_index.yar
    files = sorted(p.name for p in rules_dir.glob("neo23x0_*.yar"))
    assert "neo23x0_rule_gen_1.yar" in files
    assert "neo23x0_rule_gen_2.yar" in files
    assert "neo23x0_rule_mal_A.yar" in files
    assert "neo23x0_base_index.yar" not in files


def test_yara_downloader_records_history(db: Database, rules_dir: Path) -> None:
    archive_bytes = _make_fake_signature_base_zip()
    stub = _StubGitHubSource(archive_bytes)
    dl = YaraRuleDownloader(db=db, rules_dir=rules_dir, github_source=stub)  # type: ignore[arg-type]
    dl.download_and_merge()

    rows = db.fetchall(
        "SELECT component, status, details FROM update_history "
        "WHERE component='yara_rules' ORDER BY applied_at DESC LIMIT 1"
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["component"] == "yara_rules"
    assert row["status"] == "APPLIED"
    assert "rules=3" in row["details"]


def test_yara_downloader_list_and_clear(db: Database, rules_dir: Path) -> None:
    archive_bytes = _make_fake_signature_base_zip()
    stub = _StubGitHubSource(archive_bytes)
    dl = YaraRuleDownloader(db=db, rules_dir=rules_dir, github_source=stub)  # type: ignore[arg-type]
    dl.download_and_merge()

    listed = dl.list_downloaded_rules()
    assert len(listed) == 3
    names = {r["filename"] for r in listed}
    assert "neo23x0_rule_gen_1.yar" in names

    removed = dl.clear_downloaded_rules()
    assert removed == 3
    assert list(rules_dir.glob("neo23x0_*.yar")) == []


def test_yara_downloader_preserves_user_rules(db: Database, rules_dir: Path) -> None:
    """User's own sample.yar must be untouched by clear()."""
    user_rule = rules_dir / "sample.yar"
    _write_yar(user_rule, "UserRule", "user_marker")

    archive_bytes = _make_fake_signature_base_zip()
    stub = _StubGitHubSource(archive_bytes)
    dl = YaraRuleDownloader(db=db, rules_dir=rules_dir, github_source=stub)  # type: ignore[arg-type]
    dl.download_and_merge()
    dl.clear_downloaded_rules()

    assert user_rule.exists()
    assert list(rules_dir.glob("neo23x0_*.yar")) == []


def test_yara_downloader_handles_failed_download(db: Database, rules_dir: Path) -> None:
    """If the archive download fails, the result should report failure + history."""
    from itshield.update.http_source import DownloadResult

    class _FailingSource:
        def download(self, dest_path):
            return DownloadResult(
                success=False, url="stub://fail", status="NETWORK_ERROR",
                detail="simulated failure",
            )

    dl = YaraRuleDownloader(
        db=db, rules_dir=rules_dir, github_source=_FailingSource(),  # type: ignore[arg-type]
    )
    result = dl.download_and_merge()
    assert not result.success
    assert result.status == "NETWORK_ERROR"
    rows = db.fetchall(
        "SELECT status FROM update_history WHERE component='yara_rules'"
    )
    assert any(r["status"] == "FAILED_DOWNLOAD" for r in rows)
