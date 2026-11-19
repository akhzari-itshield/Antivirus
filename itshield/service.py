"""ITShield service module - wires Core, EventBus, Storage, IPC together.

This module is the bootstrap that ``itshield serve`` and the GUI use to
start a fully wired Core Manager with the IPC server listening on the
configured Unix Domain Socket.

The wiring is intentionally minimal: Phase 1-5 only requires Core,
EventBus, Storage and IPC to be alive. Scanner and Detection are
constructed lazily by the CLI / IPC handler when a scan is requested.
"""

from __future__ import annotations

import threading
from typing import Optional

from itshield.core.manager import CoreManager, CoreState, ModuleProtocol
from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.ipc.server import IPCServer
from itshield.logging.logger import get_logger
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations

logger = get_logger(__name__)


class _EventBusModule(ModuleProtocol):
    """Wraps EventBus so it fits the Core's ModuleProtocol contract."""

    name = "event_bus"
    dependencies: tuple[str, ...] = ()

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus

    def start(self) -> None:
        self._bus.publish(
            Event(
                event_type=EventType.SECURITY_ALERT,
                source="core",
                severity=Severity.INFO,
                metadata={"message": "ITShield Core starting"},
            )
        )

    def stop(self) -> None:
        self._bus.clear()

    def health(self) -> dict:
        return self._bus.stats()


class _StorageModule(ModuleProtocol):
    """Wraps Database so it fits the Core's ModuleProtocol contract."""

    name = "storage"
    dependencies: tuple[str, ...] = ()

    def __init__(self, db: Database) -> None:
        self._db = db

    def start(self) -> None:
        run_migrations(self._db)

    def stop(self) -> None:
        pass

    def health(self) -> dict:
        try:
            row = self._db.fetchone("SELECT COUNT(*) AS c FROM scan_jobs")
            return {"connected": True, "scan_jobs": dict(row)["c"] if row else 0}
        except Exception as exc:
            return {"connected": False, "error": str(exc)}


class _IPCModule(ModuleProtocol):
    """Wraps IPCServer so it fits the Core's ModuleProtocol contract."""

    name = "ipc"
    dependencies: tuple[str, ...] = ("event_bus", "storage")

    def __init__(self, server: IPCServer) -> None:
        self._server = server
        self._started = False

    def start(self) -> None:
        self._server.start()
        self._started = True

    def stop(self) -> None:
        if self._started:
            self._server.stop()
            self._started = False

    def health(self) -> dict:
        return {
            "socket_path": str(self._server.socket_path),
            "running": self._started,
        }


def build_core(
    socket_path: Optional[str] = None,
    db_path: Optional[str] = None,
) -> tuple[CoreManager, Database, EventBus, IPCServer]:
    """Construct a fully wired CoreManager and its dependencies.

    Returns the four top-level handles so callers (CLI, GUI, tests) can
    reach into them without traversing the CoreManager.
    """
    from itshield.config.settings import get_settings

    settings = get_settings()
    if db_path:
        from pathlib import Path
        db = Database(Path(db_path))
    else:
        db = Database(settings.db_path)

    bus = EventBus()
    core = CoreManager()

    ipc_server = IPCServer(core, socket_path=socket_path) if socket_path else IPCServer(core)

    core.register(_StorageModule(db))
    core.register(_EventBusModule(bus))
    core.register(_IPCModule(ipc_server))

    return core, db, bus, ipc_server


def run_service(socket_path: Optional[str] = None, db_path: Optional[str] = None) -> int:
    """Start the ITShield Core service and block until Ctrl-C.

    Used by ``itshield serve``.
    """
    core, db, bus, server = build_core(socket_path=socket_path, db_path=db_path)

    try:
        core.start()
        if core.state in (CoreState.FAILED,):
            logger.error("Core failed to start; exiting")
            return 1

        logger.info("ITShield service ready. Press Ctrl-C to stop.")
        while core.state not in (CoreState.STOPPED, CoreState.FAILED):
            threading.Event().wait(0.5)
    except KeyboardInterrupt:
        logger.info("Interrupt received; stopping Core")
    finally:
        core.stop()
        db.close()

    return 0
