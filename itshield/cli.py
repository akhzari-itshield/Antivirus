"""ITShield command-line entry point.

Usage::

    itshield --help
    itshield serve                      # start Core + IPC server
    itshield scan /path/to/scan         # one-shot scan
    itshield jobs                       # list recent scan jobs
    itshield job <job-id>               # show details of a job
    itshield status                     # query a running Core via IPC
    itshield health                     # query Core health via IPC
    itshield quarantine list            # list quarantined files
    itshield quarantine show <id>       # show details of a quarantined file
    itshield quarantine restore <id> <path>   # restore a quarantined file
    itshield quarantine delete <id>     # permanently delete a quarantined file
    itshield watch <path>               # start real-time protection on a directory
    itshield processes                  # list running processes (Linux)
    itshield connections                # list network connections (Linux)

When invoked without arguments, prints a short help.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

from itshield.logging.logger import init_logging, get_logger
from itshield.config.settings import get_settings

init_logging()
logger = get_logger("cli")


def _cmd_serve(args: argparse.Namespace) -> int:
    from itshield.service import run_service
    return run_service(socket_path=args.socket, db_path=args.db)


def _cmd_scan(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from test_scanner import main as scan_main
    return scan_main([args.path] if args.path else [])


def _cmd_jobs(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from test_scanner import main as scan_main
    return scan_main(["--list-jobs"])


def _cmd_job(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from test_scanner import main as scan_main
    return scan_main(["--job", args.job_id])


def _cmd_status(args: argparse.Namespace) -> int:
    from itshield.ipc.client import IPCClient, IPCError
    try:
        with IPCClient(socket_path=args.socket) as client:
            status = client.core_status()
    except (IPCError, ConnectionError) as exc:
        print(f"Failed to query Core status: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(status, indent=2, default=str))
    return 0


def _cmd_health(args: argparse.Namespace) -> int:
    from itshield.ipc.client import IPCClient, IPCError
    try:
        with IPCClient(socket_path=args.socket) as client:
            health = client.core_health()
    except (IPCError, ConnectionError) as exc:
        print(f"Failed to query Core health: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(health, indent=2, default=str))
    return 0


def _open_db(args: argparse.Namespace):
    """Open the SQLite database and run migrations; return (db, qengine?)."""
    from itshield.config.settings import get_settings
    from itshield.storage.database import Database
    from itshield.storage.migrations import run_migrations
    settings = get_settings()
    db = Database(args.db or settings.db_path)
    run_migrations(db)
    return db


def _cmd_quarantine_list(args: argparse.Namespace) -> int:
    from itshield.quarantine.engine import QuarantineEngine
    db = _open_db(args)
    try:
        qe = QuarantineEngine(db=db)
        entries = qe.list_quarantined()
        if not entries:
            print("No quarantined files.")
            return 0
        print(f"{'ID':<5} {'SHA-256':<16}  {'Size':<10}  {'Original path'}")
        print("-" * 80)
        for e in entries:
            sha = (e["sha256"] or "-")[:16]
            size = e["size"] or 0
            print(f"{e['id']:<5} {sha:<16}  {size:<10}  {e['original_path']}")
    finally:
        db.close()
    return 0


def _cmd_quarantine_show(args: argparse.Namespace) -> int:
    from itshield.quarantine.engine import QuarantineEngine
    db = _open_db(args)
    try:
        qe = QuarantineEngine(db=db)
        entry = qe.get_entry(args.id)
        if entry is None:
            print(f"No quarantined entry with id {args.id}", file=sys.stderr)
            return 1
        print(json.dumps(entry, indent=2, default=str))
    finally:
        db.close()
    return 0


def _cmd_quarantine_restore(args: argparse.Namespace) -> int:
    from itshield.quarantine.engine import QuarantineEngine
    db = _open_db(args)
    try:
        qe = QuarantineEngine(db=db)
        result = qe.restore(args.id, args.target)
        print(json.dumps(result, indent=2))
    finally:
        db.close()
    return 0


def _cmd_quarantine_delete(args: argparse.Namespace) -> int:
    from itshield.quarantine.engine import QuarantineEngine
    db = _open_db(args)
    try:
        qe = QuarantineEngine(db=db)
        result = qe.delete_permanent(args.id)
        print(json.dumps(result, indent=2))
    finally:
        db.close()
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    """Start real-time protection on a directory (foreground)."""
    from itshield.events.bus import EventBus
    from itshield.quarantine.engine import QuarantineEngine
    from itshield.realtime.protection import RealTimeProtection
    from itshield.scanner.file_analyzer import FileAnalyzer
    from itshield.scanner.hash_engine import HashEngine
    from itshield.scanner.scanner import FileScanner
    from itshield.scanner.signature_engine import SignatureEngine
    from itshield.scanner.yara_engine import YaraEngine

    target = Path(args.path).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        print(f"Watch target is not a directory: {target}", file=sys.stderr)
        return 1

    bus = EventBus()
    db = _open_db(args)
    try:
        qe = QuarantineEngine(db=db) if args.auto_quarantine else None
        scanner = FileScanner(
            hash_engine=HashEngine(),
            signature_engine=SignatureEngine(),
            yara_engine=YaraEngine(),
            analyzer=FileAnalyzer(),
        )
        rtp = RealTimeProtection(
            bus=bus,
            scanner=scanner,
            watch_root=target,
            auto_quarantine=args.auto_quarantine,
            quarantine_engine=qe,
        )

        def _log(event):
            from itshield.events.models import EventType
            if event.event_type == EventType.THREAT_DETECTED:
                print(f"[THREAT] {event.file_path}: {event.metadata.get('reason')}")
            elif event.event_type == EventType.SECURITY_ALERT:
                print(f"[ALERT ] {event.file_path}: {event.metadata.get('reason')}")

        bus.subscribe(_log)

        rtp.start()
        print(f"Real-time protection active on {target}")
        print(f"Auto-quarantine: {'ON' if args.auto_quarantine else 'OFF'}")
        print("Press Ctrl-C to stop.")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nStopping...")
        finally:
            rtp.stop()
    finally:
        db.close()
    return 0


def _cmd_processes(args: argparse.Namespace) -> int:
    """List running processes (Linux /proc)."""
    from itshield.collectors.process_monitor import ProcessMonitor
    from itshield.events.bus import EventBus
    bus = EventBus()  # unused but required for constructor
    pm = ProcessMonitor(bus=bus, interval_seconds=1.0)
    procs = pm.list_processes()
    print(f"{'PID':<8} {'PPID':<8} {'UID':<8} {'STATE':<6} {'NAME'}")
    print("-" * 60)
    for p in sorted(procs, key=lambda x: x.pid):
        print(f"{p.pid:<8} {p.ppid:<8} {p.uid:<8} {p.state:<6} {p.name}")
    print(f"\nTotal: {len(procs)} processes")
    return 0


def _cmd_connections(args: argparse.Namespace) -> int:
    """List network connections (Linux /proc/net)."""
    from itshield.collectors.network_monitor import NetworkMonitor
    from itshield.events.bus import EventBus
    bus = EventBus()
    nm = NetworkMonitor(bus=bus, interval_seconds=1.0)
    conns = nm.list_connections()
    print(f"{'PROTO':<6} {'LOCAL':<24} {'REMOTE':<24} {'STATE':<12}")
    print("-" * 70)
    for c in conns:
        local = f"{c.local_addr}:{c.local_port}"
        remote = f"{c.remote_addr}:{c.remote_port}"
        print(f"{c.protocol:<6} {local:<24} {remote:<24} {c.state:<12}")
    print(f"\nTotal: {len(conns)} connections")
    return 0


def _cmd_update_yara(args: argparse.Namespace) -> int:
    """Download YARA rules from a GitHub repo.

    Phase 9: default to neo23x0/signature-base.
    Phase 12: --source <key> selects from the curated registry
              (elastic, reversinglabs, inquest, bartblaze, deadbits, ...).
              --all downloads from every source in the registry.
              --list-sources shows the registry.
    """
    import json as _json
    from itshield.update.yara_downloader import (
        YaraRuleDownloader, DEFAULT_REPO, DEFAULT_REF,
    )
    from itshield.update.yara_sources import (
        YARA_SOURCES, get_source, list_sources, sources_summary,
    )
    from itshield.update.http_source import GitHubArchiveSource

    settings = get_settings()
    db = _open_db(args)

    if args.list_sources:
        print(f"{'Key':<18} {'Repository':<40} {'Stars':<8} {'Description'}")
        print("-" * 100)
        for s in list_sources():
            print(f"{s.key:<18} {s.repo:<40} {s.stars:<8} {s.description[:50]}")
        print(f"\nTotal: {len(YARA_SOURCES)} sources")
        db.close()
        return 0

    try:
        if args.list:
            all_files = []
            for src in YARA_SOURCES:
                downloader = YaraRuleDownloader(
                    db=db, rules_dir=settings.rules_dir,
                    github_source=GitHubArchiveSource(repo=src.repo, ref=src.ref),
                    file_prefix=src.effective_prefix,
                )
                all_files.extend(downloader.list_downloaded_rules())
            if not all_files:
                print("No downloaded YARA rule files yet.")
                return 0
            print(f"{'Filename':<45} {'Size':<10} {'Modified'}")
            print("-" * 80)
            for r in all_files:
                print(f"{r['filename']:<45} {r['size']:<10} {r['modified']}")
            print(f"\nTotal: {len(all_files)} files")
            return 0

        if args.clear:
            total = 0
            for src in YARA_SOURCES:
                downloader = YaraRuleDownloader(
                    db=db, rules_dir=settings.rules_dir,
                    github_source=GitHubArchiveSource(repo=src.repo, ref=src.ref),
                    file_prefix=src.effective_prefix,
                )
                total += downloader.clear_downloaded_rules()
            print(f"Cleared {total} downloaded YARA rule files.")
            return 0

        if args.all:
            targets = list(YARA_SOURCES)
        elif args.source:
            src = get_source(args.source)
            if src is None:
                print(f"Unknown source: {args.source!r}", file=sys.stderr)
                print(f"Available: {', '.join(s.key for s in YARA_SOURCES)}", file=sys.stderr)
                return 1
            targets = [src]
        else:
            targets = [get_source("neo23x0")]

        total_added = 0
        for src in targets:
            print(f"\n=== Downloading from {src.name} ({src.repo}) ===")
            downloader = YaraRuleDownloader(
                db=db, rules_dir=settings.rules_dir,
                github_source=GitHubArchiveSource(repo=src.repo, ref=src.ref),
                file_prefix=src.effective_prefix,
                subdirs=src.subdirs,
            )
            result = downloader.download_and_merge()
            if result.success:
                print(f"  Done: {result.rules_downloaded} rule files merged "
                      f"(skipped {result.rules_skipped}, errors {len(result.errors)})")
                total_added += result.rules_downloaded
            else:
                print(f"  Failed: {result.status}")
                for e in result.errors[:3]:
                    print(f"    - {e}")

        print(f"\n=== Summary: {total_added} total rule files added from {len(targets)} sources ===")
    finally:
        db.close()
    return 0


def _cmd_update_ioc(args: argparse.Namespace) -> int:
    """Download IOCs from abuse.ch feeds (ThreatFox, URLHaus, FeodoTracker)."""
    import json as _json
    from itshield.update.ioc_downloader import (
        IOCDownloader, IOC_SOURCES, get_ioc_source,
    )

    settings = get_settings()
    db = _open_db(args)
    try:
        if args.list_sources:
            print(f"{'Key':<15} {'Name':<20} {'API URL'}")
            print("-" * 80)
            for key, cls in IOC_SOURCES.items():
                src = cls()
                print(f"{key:<15} {src.name:<20} {src.API_URL if hasattr(src, 'API_URL') else '-'}")
            return 0

        if args.list:
            from itshield.update.ioc_downloader import IOCDownloader
            dl = IOCDownloader(db=db)
            counts = dl.count_all()
            print("IOC database counts:")
            for table, count in counts.items():
                print(f"  {table:<15} {count}")
            for table in ("ioc_hashes", "ioc_ips", "ioc_domains", "ioc_urls"):
                rows = db.fetchall(
                    f"SELECT source, COUNT(*) AS c FROM {table} GROUP BY source"
                )
                for r in rows:
                    print(f"    {table} / {r['source']}: {r['c']}")
            return 0

        if args.source:
            try:
                src = get_ioc_source(args.source)
            except KeyError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 1
            sources = [src]
        else:
            sources = [cls() for cls in IOC_SOURCES.values()]

        total_added = 0
        for src in sources:
            print(f"\n=== Downloading IOCs from {src.name} ===")
            downloader = IOCDownloader(db=db, source=src)
            result = downloader.download_and_merge(limit=args.limit)
            print(_json.dumps(result.to_dict(), indent=2, default=str))
            if result.success:
                total_added += result.iocs_added
                print(f"  Done: {result.iocs_added} IOCs added "
                      f"(duplicates: {result.iocs_duplicate})")
            else:
                print(f"  Status: {result.status}")
                for e in result.errors[:3]:
                    print(f"    - {e}")

        print(f"\n=== Summary: {total_added} total IOCs added from {len(sources)} sources ===")
    finally:
        db.close()
    return 0


def _cmd_update_hashes(args: argparse.Namespace) -> int:
    """Download SHA-256 malware hashes from MalwareBazaar and merge into the bank."""
    import json as _json
    from itshield.update.hash_downloader import HashBankDownloader, MalwareBazaarSource

    settings = get_settings()
    db = _open_db(args)
    try:
        source = MalwareBazaarSource()
        downloader = HashBankDownloader(
            db=db,
            bank_path=settings.signature_bank_path,
            backup_dir=settings.data_dir / "bank_backups",
            source=source,
        )
        print(f"Downloading SHA-256 hashes from {source.name} (limit={args.limit})...")
        result = downloader.download_and_merge(limit=args.limit)
        print()
        print(_json.dumps(result.to_dict(), indent=2, default=str))
        if result.success:
            print(f"\nDone: bank updated v{result.bank_version_before} -> v{result.bank_version_after}")
            print(f"  Hashes fetched:    {result.hashes_fetched}")
            print(f"  Hashes added:      {result.hashes_added}")
            print(f"  Duplicates skipped: {result.hashes_duplicate}")
            print(f"  Bank size:         {result.bank_size_before} -> {result.bank_size_after}")
        else:
            print(f"\nDownload status: {result.status}")
            for e in result.errors:
                print(f"  - {e}")
            return 1
    finally:
        db.close()
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Generate a report (HTML/JSON/text) for a scan job."""
    from itshield.reporting.report_generator import ReportGenerator, ReportFormat

    settings = get_settings()
    db = _open_db(args)
    try:
        gen = ReportGenerator(db=db, reports_dir=settings.reports_dir)
        fmt = ReportFormat(args.format)
        try:
            path = gen.generate(args.job_id, fmt=fmt)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Report generated: {path}")
        print(f"  Format: {fmt.value}")
        print(f"  Job:    {args.job_id}")
    finally:
        db.close()
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 key pair for signing update packages."""
    from itshield.update.signed_verifier import generate_keypair, save_keypair
    pair = generate_keypair()
    private_path = Path(args.private)
    public_path = Path(args.public)
    save_keypair(pair, private_path, public_path)
    print(f"Generated Ed25519 key pair:")
    print(f"  Private: {private_path}  (keep this secret!)")
    print(f"  Public:  {public_path}  (ship with the product for verification)")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    """Sign a bank file with an Ed25519 private key."""
    from itshield.update.signed_verifier import UpdateSigner
    signer = UpdateSigner(private_key_path=args.private)
    sig_path = signer.sign_and_write(args.file)
    sha, sig_b64 = signer.sign_file(args.file)
    print(f"Signed: {args.file}")
    print(f"  Signature sidecar: {sig_path}")
    print(f"  SHA-256: {sha}")
    print(f"  Signature (b64): {sig_b64[:32]}...")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify a bank file's signature against a public key."""
    from itshield.update.signed_verifier import SignedVerifier
    verifier = SignedVerifier(public_key_path=args.public)
    result = verifier.verify_file(args.file)
    if result.ok:
        print(f"OK: signature valid for {args.file}")
        print(f"  SHA-256: {result.bank_sha256}")
        return 0
    else:
        print(f"FAIL: {result.status} - {result.detail}", file=sys.stderr)
        return 1


def _cmd_export_settings(args: argparse.Namespace) -> int:
    """Export current settings to a JSON file."""
    from itshield.config.settings_io import export_settings
    path = export_settings(args.output)
    print(f"Settings exported to: {path}")
    return 0


def _cmd_import_settings(args: argparse.Namespace) -> int:
    """Import settings from a JSON file and apply them."""
    from itshield.config.settings_io import import_settings
    try:
        data = import_settings(args.input, apply=True)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Settings imported from: {args.input}")
    print(f"  Applied {len(data)} fields to live config.")
    return 0


def _cmd_sandbox(args: argparse.Namespace) -> int:
    """Run a suspicious file in the sandbox and report observed behavior."""
    import json as _json
    from itshield.sandbox.analyzer import SandboxAnalyzer

    analyzer = SandboxAnalyzer(timeout_seconds=args.timeout)
    report = analyzer.analyze(args.file)
    print(_json.dumps(report.to_dict(), indent=2, default=str))

    from itshield.sandbox.analyzer import SandboxVerdict
    if report.verdict == SandboxVerdict.MALICIOUS:
        return 2
    elif report.verdict == SandboxVerdict.SUSPICIOUS:
        return 1
    elif report.verdict == SandboxVerdict.TIMEOUT:
        return 1
    elif report.verdict == SandboxVerdict.ERROR:
        return 3
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="itshield",
        description="ITShield Antivirus - endpoint protection platform (Phase 1-6)",
    )
    parser.add_argument(
        "--socket",
        help="Override IPC socket path (default: $XDG_RUNTIME_DIR/itshield.sock or /tmp/itshield.sock).",
    )
    parser.add_argument(
        "--db",
        help="Override SQLite database path.",
    )
    sub = parser.add_subparsers(dest="command", required=False)

    p_serve = sub.add_parser("serve", help="Start the ITShield Core service (IPC server).")
    p_serve.set_defaults(func=_cmd_serve)

    p_scan = sub.add_parser("scan", help="Scan a file or directory.")
    p_scan.add_argument("path", nargs="?", help="Path to scan.")
    p_scan.set_defaults(func=_cmd_scan)

    p_jobs = sub.add_parser("jobs", help="List recent scan jobs.")
    p_jobs.set_defaults(func=_cmd_jobs)

    p_job = sub.add_parser("job", help="Show details of a scan job.")
    p_job.add_argument("job_id", help="Job id.")
    p_job.set_defaults(func=_cmd_job)

    p_status = sub.add_parser("status", help="Query Core status via IPC.")
    p_status.set_defaults(func=_cmd_status)

    p_health = sub.add_parser("health", help="Query Core health via IPC.")
    p_health.set_defaults(func=_cmd_health)

    p_q = sub.add_parser("quarantine", help="Manage quarantined files.")
    q_sub = p_q.add_subparsers(dest="q_command", required=True)
    q_sub.add_parser("list", help="List quarantined files.").set_defaults(func=_cmd_quarantine_list)
    p_q_show = q_sub.add_parser("show", help="Show details of a quarantined file.")
    p_q_show.add_argument("id", type=int, help="Quarantine row id.")
    p_q_show.set_defaults(func=_cmd_quarantine_show)
    p_q_restore = q_sub.add_parser("restore", help="Restore a quarantined file.")
    p_q_restore.add_argument("id", type=int, help="Quarantine row id.")
    p_q_restore.add_argument("target", help="Path to restore the file to.")
    p_q_restore.set_defaults(func=_cmd_quarantine_restore)
    p_q_del = q_sub.add_parser("delete", help="Permanently delete a quarantined file.")
    p_q_del.add_argument("id", type=int, help="Quarantine row id.")
    p_q_del.set_defaults(func=_cmd_quarantine_delete)

    p_watch = sub.add_parser("watch", help="Start real-time protection on a directory.")
    p_watch.add_argument("path", help="Directory to watch.")
    p_watch.add_argument(
        "--auto-quarantine", action="store_true",
        help="Automatically quarantine files flagged as MALICIOUS.",
    )
    p_watch.set_defaults(func=_cmd_watch)

    p_procs = sub.add_parser("processes", help="List running processes (Linux /proc).")
    p_procs.set_defaults(func=_cmd_processes)

    p_conns = sub.add_parser("connections", help="List network connections (Linux /proc/net).")
    p_conns.set_defaults(func=_cmd_connections)

    p_upd = sub.add_parser("update", help="Update signature banks and YARA rules.")
    upd_sub = p_upd.add_subparsers(dest="upd_command", required=True)

    p_yara = upd_sub.add_parser(
        "yara",
        help="Download YARA rules from a GitHub repo (default: neo23x0/signature-base).",
    )
    p_yara.add_argument(
        "--source", default=None,
        help="Source key from the registry (elastic, reversinglabs, inquest, bartblaze, ...).",
    )
    p_yara.add_argument(
        "--all", action="store_true",
        help="Download from every source in the registry (12 sources).",
    )
    p_yara.add_argument(
        "--list-sources", action="store_true",
        help="List all available YARA rule sources and exit.",
    )
    p_yara.add_argument(
        "--repo", default=None,
        help="Custom GitHub repo in owner/name form (overrides --source).",
    )
    p_yara.add_argument(
        "--ref", default=None,
        help="Branch or tag to download (default: master/main).",
    )
    p_yara.add_argument(
        "--list", action="store_true",
        help="List already-downloaded YARA rule files and exit.",
    )
    p_yara.add_argument(
        "--clear", action="store_true",
        help="Remove all downloaded YARA rule files (preserves sample.yar).",
    )
    p_yara.set_defaults(func=_cmd_update_yara)

    p_hashes = upd_sub.add_parser(
        "hashes",
        help="Download SHA-256 malware hashes from MalwareBazaar (abuse.ch).",
    )
    p_hashes.add_argument(
        "--limit", type=int, default=1000,
        help="Maximum number of recent hashes to fetch (default: 1000, max: 1000).",
    )
    p_hashes.set_defaults(func=_cmd_update_hashes)

    p_ioc = upd_sub.add_parser(
        "ioc",
        help="Download IOCs from abuse.ch feeds (ThreatFox, URLHaus, FeodoTracker).",
    )
    p_ioc.add_argument(
        "--source", default=None,
        help="IOC source key: threatfox, urlhaus, feodo. Default: all.",
    )
    p_ioc.add_argument(
        "--list-sources", action="store_true",
        help="List available IOC sources and exit.",
    )
    p_ioc.add_argument(
        "--list", action="store_true",
        help="Show IOC database counts and exit.",
    )
    p_ioc.add_argument(
        "--limit", type=int, default=1000,
        help="Maximum IOCs to fetch per source (default: 1000).",
    )
    p_ioc.set_defaults(func=_cmd_update_ioc)

    p_report = sub.add_parser("report", help="Generate a scan report (HTML/JSON/text).")
    p_report.add_argument("job_id", help="Scan job id.")
    p_report.add_argument(
        "--format", choices=["html", "json", "text"], default="html",
        help="Report format (default: html).",
    )
    p_report.set_defaults(func=_cmd_report)

    p_keygen = sub.add_parser(
        "keygen",
        help="Generate an Ed25519 key pair for signing update packages.",
    )
    p_keygen.add_argument("--private", required=True, help="Output path for private key (PEM).")
    p_keygen.add_argument("--public", required=True, help="Output path for public key (PEM).")
    p_keygen.set_defaults(func=_cmd_keygen)

    p_sign = sub.add_parser(
        "sign",
        help="Sign a bank file with an Ed25519 private key (creates a .sig sidecar).",
    )
    p_sign.add_argument("--private", required=True, help="Private key PEM path.")
    p_sign.add_argument("file", help="File to sign.")
    p_sign.set_defaults(func=_cmd_sign)

    p_verify = sub.add_parser(
        "verify",
        help="Verify a bank file's signature against a public key.",
    )
    p_verify.add_argument("--public", required=True, help="Public key PEM path.")
    p_verify.add_argument("file", help="File to verify (must have a .sig sidecar).")
    p_verify.set_defaults(func=_cmd_verify)

    p_export = sub.add_parser(
        "export-settings",
        help="Export current settings to a JSON file.",
    )
    p_export.add_argument("output", help="Output JSON path.")
    p_export.set_defaults(func=_cmd_export_settings)

    p_import = sub.add_parser(
        "import-settings",
        help="Import settings from a JSON file and apply them to the live config.",
    )
    p_import.add_argument("input", help="Input JSON path.")
    p_import.set_defaults(func=_cmd_import_settings)

    p_sandbox = sub.add_parser(
        "sandbox",
        help="Run a suspicious file in an isolated sandbox and report behavior.",
    )
    p_sandbox.add_argument("file", help="Path to the file to analyze.")
    p_sandbox.add_argument(
        "--timeout", type=float, default=10.0,
        help="Hard kill timeout in seconds (default: 10).",
    )
    p_sandbox.set_defaults(func=_cmd_sandbox)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "func", None):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
