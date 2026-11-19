"""Events tab - live event stream from the EventBus."""

from __future__ import annotations

from collections import deque
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType
from itshield.gui.styles import get_palette
from itshield.gui.widgets import make_section_title


_EVENT_FILTERS: list[tuple[str, Optional[EventType]]] = [
    ("همه رویدادها", None),
    ("ایجاد فایل", EventType.FILE_CREATED),
    ("تغییر فایل", EventType.FILE_MODIFIED),
    ("حذف فایل", EventType.FILE_DELETED),
    ("ایجاد پردازه", EventType.PROCESS_CREATED),
    ("پایان پردازه", EventType.PROCESS_TERMINATED),
    ("اتصال شبکه", EventType.NETWORK_CONNECTION),
    ("تهديد شناسایی‌شده", EventType.THREAT_DETECTED),
    ("هشدار امنیتی", EventType.SECURITY_ALERT),
]


class EventsTab(QWidget):
    """Live event streamer with filter + pause/clear."""

    def __init__(
        self,
        bus: EventBus,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._bus = bus
        self._paused = False
        self._buffer: deque[Event] = deque(maxlen=1000)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(make_section_title("رویدادهای زنده"))
        sub = QLabel("جریان زنده رویدادها از EventBus — قابل فیلتر و توقف")
        sub.setObjectName("subtitle")
        layout.addWidget(sub)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("فیلتر:"))
        self.filter_combo = QComboBox()
        for label, _ in _EVENT_FILTERS:
            self.filter_combo.addItem(label)
        self.filter_combo.currentIndexChanged.connect(self._refresh_table)
        ctrl.addWidget(self.filter_combo)
        ctrl.addStretch()
        self.pause_btn = QPushButton("توقف")
        self.pause_btn.clicked.connect(self._toggle_pause)
        ctrl.addWidget(self.pause_btn)
        clear_btn = QPushButton("پاک‌سازی")
        clear_btn.clicked.connect(self._clear)
        ctrl.addWidget(clear_btn)
        layout.addLayout(ctrl)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["زمان", "نوع", "منبع", "Severity", "جزئیات"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)

        self._unsubscribe = self._bus.subscribe(self._on_event)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_table)
        self._timer.start(500)

    def _on_event(self, event: Event) -> None:
        if self._paused:
            return
        self._buffer.append(event)

    def _refresh_table(self) -> None:
        idx = self.filter_combo.currentIndex()
        _, filter_type = _EVENT_FILTERS[idx] if idx < len(_EVENT_FILTERS) else (None, None)

        events = list(self._buffer)
        if filter_type is not None:
            events = [e for e in events if e.event_type == filter_type]
        events = events[-500:]  # show last 500 max

        self.table.setRowCount(0)
        p = get_palette()
        for e in events:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(e.timestamp))
            self.table.setItem(row, 1, QTableWidgetItem(e.event_type.value))
            self.table.setItem(row, 2, QTableWidgetItem(e.source))
            self.table.setItem(row, 3, QTableWidgetItem(e.severity.value))

            detail_parts = []
            if e.process_name:
                detail_parts.append(f"proc={e.process_name}")
            if e.process_id:
                detail_parts.append(f"pid={e.process_id}")
            if e.file_path:
                detail_parts.append(f"file={e.file_path}")
            if e.file_hash:
                detail_parts.append(f"sha={e.file_hash[:8]}")
            self.table.setItem(row, 4, QTableWidgetItem(" ".join(detail_parts)))

    def _toggle_pause(self) -> None:
        self._paused = not self._paused
        self.pause_btn.setText("ادامه" if self._paused else "توقف")

    def _clear(self) -> None:
        self._buffer.clear()
        self.table.setRowCount(0)
