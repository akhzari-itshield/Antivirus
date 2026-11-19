"""Unit tests for itshield.core.manager.CoreManager."""

from __future__ import annotations

import pytest

from itshield.core.manager import CoreManager, CoreState, ModuleProtocol


class FakeModule(ModuleProtocol):
    """Minimal module used in tests."""

    def __init__(self, name: str, deps: tuple[str, ...] = (),
                 fail_start: bool = False) -> None:
        self.name = name
        self.dependencies = deps
        self._fail_start = fail_start
        self.started = False
        self.stopped = False

    def start(self) -> None:
        if self._fail_start:
            raise RuntimeError(f"{self.name} boom")
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def health(self) -> dict:
        return {"started": self.started}


def test_initial_state_is_stopped() -> None:
    core = CoreManager()
    assert core.state == CoreState.STOPPED


def test_start_with_no_modules_goes_to_running() -> None:
    core = CoreManager()
    core.start()
    assert core.state == CoreState.RUNNING
    core.stop()
    assert core.state == CoreState.STOPPED


def test_dependency_order_is_respected() -> None:
    core = CoreManager()
    order = []

    class M(FakeModule):
        def start(self):
            order.append(self.name)
            super().start()

    a = M("a", deps=("b",))
    b = M("b")
    core.register(a)
    core.register(b)
    core.start()
    assert order == ["b", "a"]


def test_failed_module_degrades_state() -> None:
    core = CoreManager()
    core.register(FakeModule("good"))
    core.register(FakeModule("bad", fail_start=True))
    core.start()
    assert core.state == CoreState.DEGRADED
    status = core.status()
    assert status["modules"]["bad"]["failed"] is True
    assert status["modules"]["good"]["started"] is True


def test_dependency_cycle_detected() -> None:
    core = CoreManager()
    core.register(FakeModule("a", deps=("b",)))
    core.register(FakeModule("b", deps=("a",)))
    with pytest.raises(RuntimeError):
        core.start()
    assert core.state == CoreState.FAILED


def test_unknown_dependency_raises() -> None:
    core = CoreManager()
    core.register(FakeModule("a", deps=("missing",)))
    with pytest.raises(RuntimeError):
        core.start()


def test_state_listener_called_on_transitions() -> None:
    core = CoreManager()
    transitions = []
    core.add_state_listener(lambda old, new: transitions.append((old.value, new.value)))
    core.start()
    core.stop()
    assert ("STOPPED", "STARTING") in transitions
    assert ("STARTING", "RUNNING") in transitions
    assert ("RUNNING", "STOPPING") in transitions
    assert ("STOPPING", "STOPPED") in transitions


def test_status_returns_module_details() -> None:
    core = CoreManager()
    core.register(FakeModule("a"))
    core.start()
    status = core.status()
    assert status["state"] == "RUNNING"
    assert "a" in status["modules"]
    assert status["modules"]["a"]["started"] is True
    assert status["modules"]["a"]["health"] == {"started": True}
    core.stop()


def test_health_summary() -> None:
    core = CoreManager()
    core.register(FakeModule("a"))
    core.register(FakeModule("b", fail_start=True))
    core.start()
    h = core.health()
    assert h["state"] == "DEGRADED"
    assert h["modules_healthy"] == 1
    assert h["modules_degraded"] == 1
    assert h["modules_total"] == 2
