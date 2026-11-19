"""Real-Time File Protection package for ITShield.

Section 14 (Real-Time Protection roadmap) of the architecture document.

Two cooperating modules:

    * :class:`FileWatcher` - thin wrapper around ``inotify_simple`` that
      watches a directory tree for create/modify/delete events and
      publishes raw FILE_CREATED / FILE_MODIFIED / FILE_DELETED events
      to the EventBus.

    * :class:`RealTimeProtection` - combines FileWatcher with FileScanner.
      On every FILE_CREATED / FILE_MODIFIED event it scans the file
      immediately; if the scanner returns MALICIOUS it publishes a
      THREAT_DETECTED event (and optionally quarantines the file via
      the QuarantineEngine).

Linux-only (inotify). On systems without inotify the watcher raises at
start() time so the Core can degrade.
"""

from itshield.realtime.watcher import FileWatcher, WatchEvent
from itshield.realtime.protection import RealTimeProtection

__all__ = ["FileWatcher", "WatchEvent", "RealTimeProtection"]
