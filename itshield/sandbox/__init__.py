"""Sandbox analysis package for ITShield (Phase 13).

Section 16 of the architecture document - "Behavioral Analysis" roadmap
item: "تحلیل فایل‌های مشکوک در محیط Sandbox".

The sandbox analyzer executes a suspicious file in an isolated temporary
directory with a strict timeout, observes what it does (child processes,
file creates, network attempts) and returns a structured report.

Safety measures (Linux):
    * The file is copied to a fresh temp directory with mode 0700.
    * Execution happens via ``subprocess`` with a hard timeout (default 10s).
    * The subprocess runs with a reduced environment (no HOME, no PATH
      inheritance beyond /usr/bin) so the file can't trivially find tools.
    * The temp directory is wiped on exit regardless of outcome.
    * We DO NOT use seccomp/cgroups in this version - that requires root
      and is out of scope for a user-space tool. The timeout + temp dir +
      env stripping is the safety boundary.

The analyzer is **NOT** a substitute for a real hardware-backed sandbox.
It is a quick triage tool: "what does this file try to do in 10 seconds?"
"""

from itshield.sandbox.analyzer import (
    SandboxAnalyzer,
    SandboxReport,
    ObservedBehavior,
)

__all__ = ["SandboxAnalyzer", "SandboxReport", "ObservedBehavior"]
