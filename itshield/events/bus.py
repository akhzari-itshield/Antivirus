"""Event Bus - the in-process pub/sub backbone of ITShield.

Section 8.1 of the architecture document.

Design:
    * Each subscriber registers for one or more :class:`EventType` values
      (or for ``None`` to receive everything).
    * Publishing is synchronous but the bus is thread-safe. A bounded queue
      plus a worker thread (Central Event Pipeline) is described in section
      8.4 but intentionally not implemented yet; the bus is the carrier, the
      pipeline will be added in a later phase.
    * Subscribers that raise are isolated: the exception is logged and the
      bus keeps delivering to remaining subscribers. This implements the
      ``Failure Isolation`` principle from section 19.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Set, Union

from itshield.events.models import Event, EventType
from itshield.logging.logger import get_logger

logger = get_logger(__name__)

Subscriber = Callable[[Event], None]


class EventBus:
    """Thread-safe pub/sub bus for normalized events."""

    def __init__(self, max_queue_size: int = 10000) -> None:
        self._lock = threading.RLock()
        self._subscribers: Dict[Optional[EventType], List[Subscriber]] = defaultdict(list)
        self._published_count: int = 0
        self._delivered_count: int = 0
        self._dropped_count: int = 0
        self._max_queue_size = max_queue_size

    def subscribe(
        self,
        subscriber: Subscriber,
        event_types: Optional[Union[EventType, List[EventType]]] = None,
    ) -> Callable[[], None]:
        """Register ``subscriber`` for ``event_types``.

        If ``event_types`` is ``None``, the subscriber receives every event.
        Returns an unsubscribe callable.
        """
        if event_types is None:
            targets: List[Optional[EventType]] = [None]
        elif isinstance(event_types, EventType):
            targets = [event_types]
        else:
            targets = list(event_types)

        with self._lock:
            for t in targets:
                self._subscribers[t].append(subscriber)

        def _unsubscribe() -> None:
            with self._lock:
                for t in targets:
                    lst = self._subscribers.get(t, [])
                    if subscriber in lst:
                        lst.remove(subscriber)

        return _unsubscribe

    def publish(self, event: Event) -> None:
        """Deliver ``event`` to every matching subscriber."""
        with self._lock:
            self._published_count += 1
            if self._published_count > self._max_queue_size:
                self._dropped_count += 1
                self._published_count = 1
                logger.warning(
                    "EventBus backpressure: published_count reset after exceeding %d",
                    self._max_queue_size,
                )

            targets = list(self._subscribers.get(None, []))
            targets += list(self._subscribers.get(event.event_type, []))

        for sub in targets:
            try:
                sub(event)
                with self._lock:
                    self._delivered_count += 1
            except Exception:
                logger.exception(
                    "Subscriber %r raised on event %s; isolating failure",
                    getattr(sub, "__name__", repr(sub)),
                    event.event_type.value,
                )

    def stats(self) -> Dict[str, int]:
        """Return counters useful for /core.health IPC reporting."""
        with self._lock:
            subscriber_count = sum(
                len(lst) for lst in self._subscribers.values()
            )
            return {
                "subscribers": subscriber_count,
                "published_total": self._published_count,
                "delivered_total": self._delivered_count,
                "dropped_total": self._dropped_count,
                "max_queue_size": self._max_queue_size,
            }

    def clear(self) -> None:
        """Remove every subscriber (used by tests)."""
        with self._lock:
            self._subscribers.clear()
            self._published_count = 0
            self._delivered_count = 0
            self._dropped_count = 0
