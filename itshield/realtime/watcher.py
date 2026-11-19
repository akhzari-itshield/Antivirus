"""FileWatcher - inotify-backed directory watcher (Linux).

Publishes FILE_CREATED / FILE_MODIFIED / FILE_DELETED events to the
EventBus whenever a file is created, modified or removed inside a
watched directory tree.

Uses ``inotify_simple`` (a thin ctypes wrapper around the inotify(7)
syscalls). The library is optional at runtime: if it isn't importable,
the watcher raises at start time so the Core can degrade.

The watcher recursively adds inotify watches for every subdirectory
under the requested root. New subdirectories created at runtime are
picked up via the IN_ISDIR flag on IN_CREATE events.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Dict, Iterable, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger
from itshield.scanner.scanner import FileScanner  # noqa: F401 - re-exported by protection

logger = get_logger(__name__)


class WatchEvent:
    """Convenience holder for one raw inotify event (used in tests)."""

    __slots__ = ("path", "mask", "is_directory")

    def __init__(self, path: str, mask: int, is_directory: bool) -> None:
        self.path = path
        self.mask = mask
        self.is_directory = is_directory


_IN_CREATE = 0x100
_IN_MODIFY = 0x00000002
_IN_DELETE = 0x200
_IN_ISDIR = 0x40000000


class FileWatcher:
    """Watch a directory tree with inotify and publish events."""

    name = "file_watcher"
    dependencies: tuple[str, ...] = ("event_bus",)

    def __init__(
        self,
        bus: EventBus,
        root: str | Path,
        recursive: bool = True,
    ) -> None:
        self._bus = bus
        self.root = Path(root).expanduser().resolve()
        self.recursive = recursive
        self._inotify = None
        self._wd_to_path: Dict[int, Path] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._events_published = 0
        self._watches_count = 0

    def start(self) -> None:
        try:
            from inotify_simple import INotify, flags
        except ImportError as exc:
            raise RuntimeError(
                "FileWatcher requires the 'inotify_simple' package and a Linux kernel with inotify. "
                f"ImportError: {exc}"
            ) from exc

        if not self.root.exists():
            raise FileNotFoundError(f"Watch root does not exist: {self.root}")
        if not self.root.is_dir():
            raise NotADirectoryError(f"Watch root is not a directory: {self.root}")

        self._flags = flags
        self._inotify = INotify()
        self._add_watch_recursive(self.root)

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="file-watcher", daemon=True
        )
        self._thread.start()
        logger.info(
            "FileWatcher started on %s (%d watches)",
            self.root, self._watches_count,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._inotify is not None:
            try:
                self._inotify.close()
            except Exception:
                pass
            self._inotify = None
        self._wd_to_path.clear()
        self._watches_count = 0
        logger.info("FileWatcher stopped (events_published=%d)", self._events_published)

    def health(self) -> dict:
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "root": str(self.root),
            "watches": self._watches_count,
            "events_published": self._events_published,
        }

    def _add_watch_recursive(self, directory: Path) -> None:
        """Add an inotify watch for ``directory`` and (if recursive) every subdir."""
        if self._inotify is None:
            return
        flags_mask = self._flags.CREATE | self._flags.MODIFY | self._flags.DELETE | self._flags.ISDIR
        try:
            wd = self._inotify.add_watch(str(directory), flags_mask)
            self._wd_to_path[wd] = directory
            self._watches_count += 1
        except OSError as exc:
            logger.warning("inotify add_watch failed for %s: %s", directory, exc)
            return

        if not self.recursive:
            return
        try:
            for child in directory.iterdir():
                if child.is_dir() and not child.is_symlink():
                    self._add_watch_recursive(child)
        except (PermissionError, OSError) as exc:
            logger.debug("Cannot iterate %s: %s", directory, exc)

    def _run_loop(self) -> None:
        assert self._inotify is not None
        while not self._stop_event.is_set():
            try:
                events = self._inotify.read(timeout=200)
            except Exception:
                logger.exception("inotify read failed")
                self._stop_event.wait(0.5)
                continue
            for ev in events:
                self._handle_inotify_event(ev)

    def _handle_inotify_event(self, ev) -> None:
        wd = ev.wd
        base = self._wd_to_path.get(wd)
        if base is None:
            return
        name = ev.name or ""
        target = base / name if name else base
        is_dir = bool(ev.mask & _IN_ISDIR)

        if self.recursive and (ev.mask & _IN_CREATE) and is_dir and target.is_dir():
            self._add_watch_recursive(target)

        if ev.mask & _IN_CREATE:
            etype = EventType.FILE_CREATED
        elif ev.mask & _IN_MODIFY:
            etype = EventType.FILE_MODIFIED
        elif ev.mask & _IN_DELETE:
            etype = EventType.FILE_DELETED
        else:
            return

        self._bus.publish(Event(
            event_type=etype,
            source=self.name,
            severity=Severity.INFO,
            file_path=str(target),
            metadata={
                "is_directory": is_dir,
                "watch_root": str(self.root),
                "mask": ev.mask,
            },
        ))
        self._events_published += 1
