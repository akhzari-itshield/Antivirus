"""Windows Registry Monitor for persistence detection (Phase 15).

Section 17 of the architecture document - persistence detection on Windows.

Monitors the Windows registry's autostart locations for changes:
    * HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    * HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
    * HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    * HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
    * HKLM\\System\\CurrentVersion\\Services (service persistence)
    * HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
      (Userinit, Shell keys)

When a new value is added or an existing one changes, the monitor
publishes a SECURITY_ALERT so the Behavior Analyzer / Correlation
Engine can chain it into an incident.

Uses ``pywin32`` (win32api, win32con) for registry access. Falls back
to no-op on Linux (where the registry doesn't exist).
"""

from __future__ import annotations

import sys
import threading
import time
from typing import Dict, List, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger

logger = get_logger(__name__)

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    try:
        import win32api
        import win32con
        _PYWIN32_AVAILABLE = True
    except ImportError:
        _PYWIN32_AVAILABLE = False
else:
    _PYWIN32_AVAILABLE = False


_HKEY_LOCAL_MACHINE = 0x80000002
_HKEY_CURRENT_USER = 0x80000001

_WATCHED_KEYS = [
    (_HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (_HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (_HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (_HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (_HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    (_HKEY_LOCAL_MACHINE,
     r"System\CurrentControlSet\Services"),
]


class WindowsRegistryMonitor:
    """Polls Windows registry autostart keys for changes."""

    name = "windows_registry_monitor"
    dependencies: tuple[str, ...] = ("event_bus",)

    def __init__(
        self,
        bus: EventBus,
        interval_seconds: float = 5.0,
    ) -> None:
        self._bus = bus
        self.interval = interval_seconds
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_state: Dict[str, Dict[str, str]] = {}  # key_path -> {value_name: value_data}
        self._snapshot_count = 0
        self._changes_detected = 0

    def start(self) -> None:
        if not _IS_WINDOWS or not _PYWIN32_AVAILABLE:
            raise RuntimeError(
                "WindowsRegistryMonitor requires Windows with pywin32."
            )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="win-reg-monitor", daemon=True
        )
        self._thread.start()
        logger.info("WindowsRegistryMonitor started (interval=%.2fs)", self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("WindowsRegistryMonitor stopped")

    def health(self) -> dict:
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "snapshots": self._snapshot_count,
            "changes_detected": self._changes_detected,
            "watched_keys": len(_WATCHED_KEYS),
        }

    def snapshot(self) -> Dict[str, Dict[str, str]]:
        """Read all watched registry keys and return their values."""
        if not _PYWIN32_AVAILABLE:
            return {}
        result: Dict[str, Dict[str, str]] = {}
        for hive, subkey in _WATCHED_KEYS:
            path = f"{hive}\\{subkey}"
            try:
                key = win32api.RegOpenKeyEx(hive, subkey, 0, win32con.KEY_READ)
                values: Dict[str, str] = {}
                i = 0
                while True:
                    try:
                        name, data, _ = win32api.RegEnumValue(key, i)
                        values[name or "(Default)"] = str(data)
                        i += 1
                    except Exception:
                        break
                win32api.RegCloseKey(key)
                result[path] = values
            except Exception:
                pass
        return result

    def list_autostart_entries(self) -> Dict[str, Dict[str, str]]:
        """One-shot: return all autostart registry entries."""
        return self.snapshot()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                current = self.snapshot()
                self._snapshot_count += 1
                self._diff_and_publish(self._last_state, current)
                self._last_state = current
            except Exception:
                logger.exception("Registry monitor cycle failed")
            self._stop_event.wait(self.interval)

    def _diff_and_publish(
        self,
        previous: Dict[str, Dict[str, str]],
        current: Dict[str, Dict[str, str]],
    ) -> None:
        for path, values in current.items():
            prev_values = previous.get(path, {})
            for name, data in values.items():
                if name not in prev_values:
                    self._publish_change(path, name, "", data, "added")
                elif prev_values[name] != data:
                    self._publish_change(path, name, prev_values[name], data, "modified")
            for name in prev_values:
                if name not in values:
                    self._publish_change(path, name, prev_values[name], "", "deleted")

    def _publish_change(
        self,
        path: str,
        name: str,
        old_data: str,
        new_data: str,
        change_type: str,
    ) -> None:
        self._changes_detected += 1
        logger.warning(
            "Registry %s: %s\\%s (old=%r, new=%r)",
            change_type, path, name, old_data[:50], new_data[:50],
        )
        self._bus.publish(Event(
            event_type=EventType.SECURITY_ALERT,
            source=self.name,
            severity=Severity.WARNING,
            metadata={
                "registry_path": path,
                "value_name": name,
                "old_data": old_data[:200],
                "new_data": new_data[:200],
                "change_type": change_type,
                "anomaly": f"persistence_registry_{change_type}",
            },
        ))
