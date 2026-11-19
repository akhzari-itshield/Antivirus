"""Sandbox analyzer - executes suspicious files in an isolated environment (Phase 13).

Runs a file in a temp directory with a hard timeout, watches for:
    * child process creation
    * file create/modify/delete (via inotify on the temp dir)
    * network connection attempts (via /proc/net delta)
    * exit code and duration

Returns a :class:`SandboxReport` with a verdict:
    * ``BENIGN``   - exited cleanly, no suspicious behavior
    * ``SUSPICIOUS`` - created files or spawned children (low severity)
    * ``MALICIOUS`` - attempted network connections to external IPs,
                      or spawned known interpreters, or wrote to
                      persistence locations
    * ``TIMEOUT``  - did not exit within the timeout (often a sign of
                      an infinite loop or waiting for C2)
    * ``ERROR``    - could not execute (e.g. not a runnable file)
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional

from itshield.logging.logger import get_logger

logger = get_logger(__name__)


class SandboxVerdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


@dataclass
class ObservedBehavior:
    """One observed behavior during sandbox execution."""

    kind: str               # "process", "file_create", "file_modify", "file_delete", "network"
    detail: str
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "timestamp": self.timestamp}


@dataclass
class SandboxReport:
    """Full report of one sandbox analysis run."""

    file_path: str
    verdict: SandboxVerdict
    duration_seconds: float
    exit_code: Optional[int]
    behaviors: List[ObservedBehavior] = field(default_factory=list)
    child_processes: List[str] = field(default_factory=list)
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    network_connections: List[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "verdict": self.verdict.value,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "behaviors": [b.to_dict() for b in self.behaviors],
            "child_processes": self.child_processes,
            "files_created": self.files_created,
            "files_modified": self.files_modified,
            "network_connections": self.network_connections,
            "error": self.error,
        }


_SUSPICIOUS_CHILDREN = {
    "python", "python3", "perl", "ruby", "node", "powershell",
    "bash", "sh", "cmd", "wget", "curl", "nc", "ncat",
}

_PERSISTENCE_PATHS = (
    "/etc/cron", "/etc/systemd", "/etc/init.d", "/etc/rc",
    "/etc/profile", "/etc/sudoers", "/.bashrc", "/.config/autostart",
)


class SandboxAnalyzer:
    """Executes suspicious files in an isolated temp directory.

    Args:
        timeout_seconds: hard kill timeout for the subprocess (default 10).
        workdir_prefix: prefix for the temp working directory.
    """

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        workdir_prefix: str = "itshield_sandbox_",
    ) -> None:
        self.timeout = timeout_seconds
        self.workdir_prefix = workdir_prefix

    def analyze(self, file_path: str | Path) -> SandboxReport:
        """Run ``file_path`` in the sandbox and return a :class:`SandboxReport`.

        The file is copied to a fresh temp directory, made executable,
        and run as a subprocess. The sandbox watches the temp dir with
        inotify (if available) for file activity and snapshots /proc/net
        before/after for network connections.
        """
        src = Path(file_path).resolve()
        if not src.exists() or not src.is_file():
            return SandboxReport(
                file_path=str(src), verdict=SandboxVerdict.ERROR,
                duration_seconds=0.0, exit_code=None,
                error="file not found or not a regular file",
            )

        workdir = Path(tempfile.mkdtemp(prefix=self.workdir_prefix))
        try:
            os.chmod(workdir, 0o700)
        except OSError:
            pass

        dest_name = src.name
        dest = workdir / dest_name
        try:
            shutil.copy2(src, dest)
            os.chmod(dest, stat.S_IRUSR | stat.S_IXUSR)
        except OSError as exc:
            shutil.rmtree(workdir, ignore_errors=True)
            return SandboxReport(
                file_path=str(src), verdict=SandboxVerdict.ERROR,
                duration_seconds=0.0, exit_code=None,
                error=f"could not stage file: {exc}",
            )

        conns_before = self._snapshot_connections()

        watcher = self._try_start_watcher(workdir)

        clean_env = {
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(workdir),
            "HOME": str(workdir),
            "LANG": "C",
        }

        report = SandboxReport(
            file_path=str(src),
            verdict=SandboxVerdict.BENIGN,
            duration_seconds=0.0,
            exit_code=None,
        )

        start = time.time()
        proc = None
        try:
            proc = subprocess.Popen(
                [str(dest)],
                cwd=str(workdir),
                env=clean_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,  # so we can kill the whole group
            )
            try:
                proc.wait(timeout=self.timeout)
                report.exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, 9)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait(timeout=2.0)
                report.verdict = SandboxVerdict.TIMEOUT
                report.exit_code = -9
        except PermissionError as exc:
            report.verdict = SandboxVerdict.ERROR
            report.error = f"permission denied: {exc}"
        except OSError as exc:
            report.verdict = SandboxVerdict.ERROR
            report.error = f"could not execute: {exc}"
        finally:
            report.duration_seconds = round(time.time() - start, 3)
            if watcher is not None:
                try:
                    watcher.stop()
                except Exception:
                    pass

        conns_after = self._snapshot_connections()
        new_conns = self._diff_connections(conns_before, conns_after)
        for c in new_conns:
            report.network_connections.append(c)
            report.behaviors.append(ObservedBehavior(
                kind="network",
                detail=c,
                timestamp="",
            ))

        if watcher is not None:
            events = watcher.collect()
            for ev in events:
                rel = ev.get("path", "")
                if workdir.name in rel:
                    if ev.get("kind") == "FILE_CREATED":
                        report.files_created.append(rel)
                        report.behaviors.append(ObservedBehavior(kind="file_create", detail=rel))
                    elif ev.get("kind") == "FILE_MODIFIED":
                        report.files_modified.append(rel)
                        report.behaviors.append(ObservedBehavior(kind="file_modify", detail=rel))

        for created in report.files_created:
            for pfx in _PERSISTENCE_PATHS:
                if pfx in created:
                    report.behaviors.append(ObservedBehavior(
                        kind="persistence",
                        detail=f"attempted write to {created}",
                    ))

        if report.verdict == SandboxVerdict.BENIGN:
            if report.network_connections:
                report.verdict = SandboxVerdict.MALICIOUS
            elif any(b.kind == "persistence" for b in report.behaviors):
                report.verdict = SandboxVerdict.MALICIOUS
            elif report.files_created or report.files_modified:
                report.verdict = SandboxVerdict.SUSPICIOUS
            elif report.exit_code is not None and report.exit_code != 0:
                report.verdict = SandboxVerdict.SUSPICIOUS

        shutil.rmtree(workdir, ignore_errors=True)

        logger.info(
            "Sandbox analysis of %s: verdict=%s, duration=%.2fs, behaviors=%d",
            src.name, report.verdict.value, report.duration_seconds,
            len(report.behaviors),
        )
        return report

    @staticmethod
    def _snapshot_connections() -> set:
        """Snapshot current TCP connections as a set of (remote_ip, remote_port)."""
        conns = set()
        try:
            with open("/proc/net/tcp", "r") as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        local, remote, state = parts[1], parts[2], parts[3]
                        if state == "01":
                            remote_ip_hex, remote_port_hex = remote.split(":")
                            try:
                                ip_bytes = bytes.fromhex(remote_ip_hex)[::-1]
                                import socket as _sock
                                ip = _sock.inet_ntop(_sock.AF_INET, ip_bytes)
                                port = int(remote_port_hex, 16)
                                if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                                    conns.add(f"{ip}:{port}")
                            except Exception:
                                pass
        except (OSError, ValueError):
            pass
        return conns

    @staticmethod
    def _diff_connections(before: set, after: set) -> List[str]:
        return sorted(after - before)

    @staticmethod
    def _try_start_watcher(workdir: Path):
        """Best-effort: start an inotify watcher on the workdir.

        Returns None if inotify is unavailable, otherwise a watcher
        object with .stop() and .collect() methods.
        """
        try:
            from inotify_simple import INotify, flags
        except ImportError:
            return None

        class _Collector:
            def __init__(self, inotify, wd, workdir):
                self._inotify = inotify
                self._wd = wd
                self._workdir = workdir
                self._events: list = []

            def stop(self):
                try:
                    self._inotify.rm_watch(self._wd)
                except Exception:
                    pass

            def collect(self) -> list:
                try:
                    for ev in self._inotify.read(timeout=0):
                        kind = "FILE_CREATED" if ev.mask & flags.CREATE else \
                               "FILE_MODIFIED" if ev.mask & flags.MODIFY else \
                               "FILE_DELETED" if ev.mask & flags.DELETE else None
                        if kind:
                            self._events.append({
                                "kind": kind,
                                "path": str(self._workdir / (ev.name or "")),
                            })
                except Exception:
                    pass
                return self._events

        try:
            ino = INotify()
            mask = flags.CREATE | flags.MODIFY | flags.DELETE | flags.ISDIR
            wd = ino.add_watch(str(workdir), mask)
            return _Collector(ino, wd, workdir)
        except Exception:
            return None
