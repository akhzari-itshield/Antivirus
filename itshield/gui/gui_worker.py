"""Thread-safe helpers for the GUI.

Background workers (scanner, watcher, collectors) must not touch Qt
widgets directly. Instead they emit :class:`BackgroundEvent` instances
via :class:`BackgroundBridge`, which marshals them to the GUI thread
through a Qt signal.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from PySide6.QtCore import QObject, Signal, Slot


@dataclass
class BackgroundEvent:
    """A marshaled event from a background thread to the GUI."""

    kind: str                       # e.g. "scan_progress", "scan_result", "scan_done"
    data: Dict[str, Any] = field(default_factory=dict)


class BackgroundBridge(QObject):
    """Marries a thread-safe queue to a Qt signal.

    Background threads call :meth:`emit` (no Qt imports needed); the GUI
    connects to :attr:`event_arrived` and receives the events on the GUI
    thread.
    """

    event_arrived = Signal(object)  # BackgroundEvent

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._lock = threading.RLock()
        self._subscribers: Dict[str, List[Callable[[BackgroundEvent], None]]] = {}

    def emit(self, event: BackgroundEvent) -> None:
        """Thread-safe: forward ``event`` to the GUI thread."""
        self.event_arrived.emit(event)

    @Slot(object)
    def dispatch(self, event: BackgroundEvent) -> None:
        """Slot called on the GUI thread; calls every subscriber for ``kind``."""
        with self._lock:
            subs = list(self._subscribers.get(event.kind, []))
            subs += list(self._subscribers.get("*", []))  # wildcard
        for sub in subs:
            try:
                sub(event)
            except Exception:
                import logging
                logging.getLogger(__name__).exception(
                    "BackgroundBridge subscriber raised for kind=%s", event.kind
                )

    def subscribe(
        self,
        kind: str,
        callback: Callable[[BackgroundEvent], None],
    ) -> Callable[[], None]:
        """Register ``callback`` for events of ``kind`` (or ``"*"`` for all).

        Returns an unsubscribe callable.
        """
        with self._lock:
            self._subscribers.setdefault(kind, []).append(callback)

        def _unsubscribe() -> None:
            with self._lock:
                lst = self._subscribers.get(kind, [])
                if callback in lst:
                    lst.remove(callback)

        return _unsubscribe

    def wire(self) -> None:
        """Connect the Qt signal to the dispatcher slot (call after moveToThread)."""
        self.event_arrived.connect(self.dispatch)
