"""Integration tests for itshield.ipc.* (server + client round trip)."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import pytest

from itshield.core.manager import CoreManager
from itshield.ipc.client import IPCClient, IPCError
from itshield.ipc.handlers import make_default_registry
from itshield.ipc.server import IPCServer
from itshield.service import _EventBusModule, _StorageModule
from itshield.events.bus import EventBus
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations


@pytest.fixture
def running_server(tmp_project: Path):
    """Spin up a real IPC server on a temp socket and tear it down after."""
    socket_path = tmp_project / "itshield-test.sock"
    db_path = tmp_project / "data" / "ipc-test.db"
    db = Database(db_path)
    run_migrations(db)

    core = CoreManager()
    core.register(_StorageModule(db))
    core.register(_EventBusModule(EventBus()))

    server = IPCServer(core, socket_path=socket_path)
    server.start()
    core.start()

    deadline = time.time() + 2.0
    while not socket_path.exists() and time.time() < deadline:
        time.sleep(0.05)

    yield core, db, socket_path

    server.stop()
    core.stop()
    db.close()


def test_core_status_round_trip(running_server) -> None:
    core, db, socket_path = running_server
    with IPCClient(socket_path=socket_path) as client:
        status = client.core_status()
    assert status["state"] == "RUNNING"
    assert "modules" in status
    assert "storage" in status["modules"]


def test_core_health_round_trip(running_server) -> None:
    core, db, socket_path = running_server
    with IPCClient(socket_path=socket_path) as client:
        health = client.core_health()
    assert health["state"] == "RUNNING"
    assert health["modules_total"] >= 2


def test_scan_request_returns_not_implemented(running_server) -> None:
    core, db, socket_path = running_server
    with IPCClient(socket_path=socket_path) as client:
        with pytest.raises(IPCError) as exc_info:
            client.scan_request("/tmp/test")
    assert exc_info.value.error_code == "SCANNER_NOT_IMPLEMENTED"


def test_unknown_operation_returns_error(running_server) -> None:
    core, db, socket_path = running_server
    with IPCClient(socket_path=socket_path) as client:
        with pytest.raises(IPCError) as exc_info:
            client.call("nonexistent.operation")
    assert exc_info.value.error_code == "UNKNOWN_OPERATION"


def test_client_fails_gracefully_when_socket_missing(tmp_project: Path) -> None:
    bogus = tmp_project / "no-such.sock"
    client = IPCClient(socket_path=bogus)
    with pytest.raises(ConnectionError):
        client.connect()
