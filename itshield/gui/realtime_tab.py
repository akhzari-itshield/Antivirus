"""Real-Time Protection tab - start/stop inotify watcher + live events."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType
from itshield.gui.gui_worker import BackgroundBridge, BackgroundEvent
from itshield.gui.styles import get_palette
from itshield.gui.widgets import StatCard, StatusIndicator, make_section_title
from itshield.quarantine.engine import QuarantineEngine
from itshield.realtime.protection import RealTimeProtection
from itshield.scanner.scanner import FileScanner


class RealtimeTab(QWidget):
    """Real-time protection tab."""

    def __init__(
        self,
        scanner: FileScanner,
        quarantine: QuarantineEngine,
        bridge: BackgroundBridge,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._scanner = scanner
        self._quarantine = quarantine
        self._bridge = bridge
        self._bus: Optional[EventBus] = None
        self._rtp: Optional[RealTimeProtection] = None
        self._events_seen = 0
        self._threats_seen = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(make_section_title("حفاظت بلادرنگ"))
        sub = QLabel("پایش زنده فایل‌ها با inotify و اسکن خودکار هنگام ایجاد یا تغییر")
        sub.setObjectName("subtitle")
        layout.addWidget(sub)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("پوشه پایش:"))
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("مثلاً /home/user/Downloads")
        path_row.addWidget(self.path_edit, 1)
        browse_btn = QPushButton("انتخاب")
        browse_btn.clicked.connect(self._browse)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)

        opts = QHBoxLayout()
        self.auto_q_check = QCheckBox("قرنطینه خودکار فایل‌های مخرب")
        self.auto_q_check.setChecked(True)
        opts.addWidget(self.auto_q_check)
        opts.addStretch()
        self.toggle_btn = QPushButton("فعال‌سازی حفاظت")
        self.toggle_btn.setObjectName("primary")
        self.toggle_btn.clicked.connect(self._toggle)
        opts.addWidget(self.toggle_btn)
        layout.addLayout(opts)

        status_row = QHBoxLayout()
        self.status = StatusIndicator("وضعیت:")
        self.events_card = StatCard("رویدادهای پایش‌شده", "0")
        self.threats_card = StatCard("تهدیدات زنده", "0", color=get_palette().malicious)
        status_row.addWidget(self.status)
        status_row.addStretch()
        status_row.addWidget(self.events_card)
        status_row.addWidget(self.threats_card)
        layout.addLayout(status_row)

        layout.addWidget(QLabel("لاگ زنده رویدادها:"))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(2000)  # auto-trim
        layout.addWidget(self.log, 1)

        self._bridge.subscribe("rtp_event", self._on_rtp_event)
        self._bridge.subscribe("rtp_threat", self._on_rtp_threat)

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "انتخاب پوشه پایش")
        if path:
            self.path_edit.setText(path)

    def _toggle(self) -> None:
        if self._rtp is not None and self._rtp.health()["running"]:
            self._stop()
        else:
            self._start()

    def _start(self) -> None:
        path = self.path_edit.text().strip()
        if not path:
            return
        target = Path(path).expanduser().resolve()
        if not target.is_dir():
            return

        self._bus = EventBus()
        def _forward(event: Event) -> None:
            self._events_seen += 1
            if event.event_type == EventType.THREAT_DETECTED:
                self._threats_seen += 1
                self._bridge.emit(BackgroundEvent(
                    kind="rtp_threat",
                    data={
                        "file_path": event.file_path,
                        "sha256": event.file_hash,
                        "reason": event.metadata.get("reason"),
                        "matched_signature": event.metadata.get("matched_signature"),
                    },
                ))
            elif event.event_type == EventType.SECURITY_ALERT:
                self._bridge.emit(BackgroundEvent(
                    kind="rtp_event",
                    data={
                        "kind": "ALERT",
                        "file_path": event.file_path,
                        "reason": event.metadata.get("reason"),
                    },
                ))
            else:
                self._bridge.emit(BackgroundEvent(
                    kind="rtp_event",
                    data={
                        "kind": event.event_type.value,
                        "file_path": event.file_path or "",
                    },
                ))
        self._bus.subscribe(_forward)

        self._rtp = RealTimeProtection(
            bus=self._bus,
            scanner=self._scanner,
            watch_root=target,
            auto_quarantine=self.auto_q_check.isChecked(),
            quarantine_engine=self._quarantine,
        )
        try:
            self._rtp.start()
        except Exception as exc:
            self.log.appendPlainText(f"[ERROR] {exc}")
            return

        p = get_palette()
        self.status.set_state("فعال", p.ok)
        self.toggle_btn.setText("توقف حفاظت")
        self.toggle_btn.setObjectName("danger")
        self.toggle_btn.style().unpolish(self.toggle_btn)
        self.toggle_btn.style().polish(self.toggle_btn)
        self.log.appendPlainText(f"[INFO] حفاظت بلادرنگ روی {target} فعال شد")

    def _stop(self) -> None:
        if self._rtp is None:
            return
        self._rtp.stop()
        self._rtp = None
        p = get_palette()
        self.status.set_state("غیرفعال", p.text_dim)
        self.toggle_btn.setText("فعال‌سازی حفاظت")
        self.toggle_btn.setObjectName("primary")
        self.toggle_btn.style().unpolish(self.toggle_btn)
        self.toggle_btn.style().polish(self.toggle_btn)
        self.log.appendPlainText("[INFO] حفاظت بلادرنگ متوقف شد")

    def _on_rtp_event(self, event: BackgroundEvent) -> None:
        d = event.data
        kind = d.get("kind", "?")
        path = d.get("file_path", "")
        name = Path(path).name if path else ""
        self.log.appendPlainText(f"[{kind}] {name}")
        self.events_card.set_value(str(self._events_seen))

    def _on_rtp_threat(self, event: BackgroundEvent) -> None:
        d = event.data
        path = d.get("file_path", "")
        reason = d.get("reason", "")
        name = Path(path).name if path else ""
        self.log.appendPlainText(
            f"[THREAT] {name} — {reason}"
        )
        self.threats_card.set_value(str(self._threats_seen))
        self.events_card.set_value(str(self._events_seen))
