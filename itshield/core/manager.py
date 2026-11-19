"""Core Manager - the lifecycle brain of ITShield.

Implements the Service-Oriented Modular Monolith pattern described in the
project architecture document (section 6).

CoreManager owns:
    * the state machine (STOPPED -> STARTING -> RUNNING -> DEGRADED -> ... -> FAILED)
    * ordered start/stop of registered modules
    * dependency resolution between modules
    * health reporting for IPC consumers (``core.status`` / ``core.health``)

A module is anything that implements the :class:`ModuleProtocol`. Real
modules (ScannerEngine, DetectionEngine, EventBus, ...) register themselves
on construction. Tests can register lightweight stub modules.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable

from itshield.logging.logger import get_logger

logger = get_logger(__name__)


class CoreState(str, Enum):
    """Lifecycle states of the Core service."""

    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    FAILED = "FAILED"


@runtime_checkable
class ModuleProtocol(Protocol):
    """Contract every ITShield module must implement.

    Modules are intentionally minimal: a name, dependencies, and start/stop.
    Health is reported through :meth:`health` so the Core can downgrade to
    ``DEGRADED`` if a non-critical module fails.
    """

    name: str
    dependencies: tuple[str, ...]

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def health(self) -> Dict[str, Any]: ...


@dataclass
class _ModuleEntry:
    """Internal bookkeeping for a registered module."""

    module: ModuleProtocol
    started: bool = False
    failed: bool = False
    last_error: Optional[str] = None


class CoreManager:
    """Lifecycle coordinator for every ITShield module.

    Thread-safety: every public mutator takes ``self._lock`` so the Core can
    be queried concurrently from IPC handlers while a scan is running.
    """

    def __init__(self) -> None:
        self._modules: Dict[str, _ModuleEntry] = {}
        self._state: CoreState = CoreState.STOPPED
        self._lock = threading.RLock()
        self._started_at: Optional[float] = None
        self._failure_reason: Optional[str] = None
        self._state_listeners: List[Callable[[CoreState, CoreState], None]] = []

    @property
    def state(self) -> CoreState:
        with self._lock:
            return self._state

    def _transition(self, new_state: CoreState, reason: Optional[str] = None) -> None:
        """Move to ``new_state`` and notify listeners. Caller holds the lock."""
        old = self._state
        if old is new_state:
            return
        self._state = new_state
        if new_state is CoreState.RUNNING:
            self._started_at = time.time()
        elif new_state in (CoreState.STOPPED, CoreState.FAILED):
            self._started_at = None
        if reason:
            self._failure_reason = reason
        logger.info("Core state transition: %s -> %s (%s)", old.value, new_state.value, reason or "-")
        for cb in list(self._state_listeners):
            try:
                cb(old, new_state)
            except Exception:  # pragma: no cover - listener must not break Core
                logger.exception("State listener raised; ignoring")

    def add_state_listener(
        self, cb: Callable[[CoreState, CoreState], None]
    ) -> None:
        with self._lock:
            self._state_listeners.append(cb)

    def register(self, module: ModuleProtocol) -> None:
        """Register a module before ``start`` is called."""
        with self._lock:
            if self._state not in (CoreState.STOPPED, CoreState.FAILED):
                raise RuntimeError(
                    f"Cannot register module {module.name!r}: core is {self._state.value}"
                )
            if module.name in self._modules:
                raise ValueError(f"Module {module.name!r} already registered")
            self._modules[module.name] = _ModuleEntry(module=module)
            logger.debug("Registered module %s (deps=%s)", module.name, module.dependencies)

    def get_module(self, name: str) -> Optional[ModuleProtocol]:
        with self._lock:
            entry = self._modules.get(name)
            return entry.module if entry else None

    def _resolve_order(self) -> List[str]:
        """Topological sort of modules respecting ``dependencies``."""
        ordered: List[str] = []
        visited: Dict[str, bool] = {}  # True = in progress (cycle detection)

        def visit(name: str) -> None:
            state = visited.get(name)
            if state is None:
                visited[name] = True
                deps = self._modules[name].module.dependencies
                for dep in deps:
                    if dep not in self._modules:
                        raise RuntimeError(
                            f"Module {name!r} depends on unknown module {dep!r}"
                        )
                    visit(dep)
                visited[name] = False
                ordered.append(name)
            elif state is True:
                raise RuntimeError(f"Dependency cycle involving {name!r}")

        for name in self._modules:
            visit(name)
        return ordered

    def start(self) -> None:
        """Start every registered module in dependency order."""
        with self._lock:
            if self._state not in (CoreState.STOPPED, CoreState.FAILED):
                logger.warning("start() called while in state %s; ignoring", self._state.value)
                return

            self._failure_reason = None
            self._transition(CoreState.STARTING)

            try:
                order = self._resolve_order()
            except RuntimeError as exc:
                self._transition(CoreState.FAILED, reason=str(exc))
                raise

            logger.info("Starting modules in order: %s", order)
            failures: List[str] = []

            for name in order:
                entry = self._modules[name]
                try:
                    entry.module.start()
                    entry.started = True
                    entry.failed = False
                    entry.last_error = None
                    logger.info("Module started: %s", name)
                except Exception as exc:
                    entry.failed = True
                    entry.last_error = str(exc)
                    failures.append(name)
                    logger.exception("Module %s failed to start", name)

            if failures:
                self._transition(
                    CoreState.DEGRADED,
                    reason=f"failed modules: {', '.join(failures)}",
                )
            else:
                self._transition(CoreState.RUNNING)

    def stop(self) -> None:
        """Stop modules in reverse dependency order."""
        with self._lock:
            if self._state in (CoreState.STOPPED, CoreState.FAILED):
                return

            self._transition(CoreState.STOPPING)
            order = self._resolve_order()[::-1]
            for name in order:
                entry = self._modules[name]
                if not entry.started:
                    continue
                try:
                    entry.module.stop()
                    entry.started = False
                    logger.info("Module stopped: %s", name)
                except Exception:
                    logger.exception("Module %s raised during stop(); continuing", name)
            self._transition(CoreState.STOPPED)

    def status(self) -> Dict[str, Any]:
        """Return a JSON-serializable status dict (consumed by IPC handlers)."""
        with self._lock:
            modules_status: Dict[str, Dict[str, Any]] = {}
            for name, entry in self._modules.items():
                modules_status[name] = {
                    "started": entry.started,
                    "failed": entry.failed,
                    "last_error": entry.last_error,
                    "dependencies": list(entry.module.dependencies),
                    "health": {},
                }
                if entry.started:
                    try:
                        modules_status[name]["health"] = entry.module.health()
                    except Exception as exc:
                        modules_status[name]["health"] = {"error": str(exc)}

            return {
                "state": self._state.value,
                "uptime_seconds": (
                    round(time.time() - self._started_at, 2)
                    if self._started_at
                    else 0.0
                ),
                "failure_reason": self._failure_reason,
                "module_count": len(self._modules),
                "modules": modules_status,
            }

    def health(self) -> Dict[str, Any]:
        """Compact health summary used by ``core.health`` IPC operation."""
        with self._lock:
            ok = sum(1 for e in self._modules.values() if e.started and not e.failed)
            degraded = sum(1 for e in self._modules.values() if e.failed)
            return {
                "state": self._state.value,
                "modules_healthy": ok,
                "modules_degraded": degraded,
                "modules_total": len(self._modules),
                "failure_reason": self._failure_reason,
            }
