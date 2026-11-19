"""System tab - processes and network connections (Linux /proc)."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
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
from itshield.collectors.process_monitor import ProcessMonitor
from itshield.collectors.network_monitor import NetworkMonitor
from itshield.gui.styles import get_palette
from itshield.gui.widgets import make_section_title


class SystemTab(QWidget):
    """Processes + Network connections in one tab (two stacked tables)."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        dummy_bus = EventBus()
        self._pm = ProcessMonitor(bus=dummy_bus, interval_seconds=1.0)
        self._nm = NetworkMonitor(bus=dummy_bus, interval_seconds=1.0)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(make_section_title("پردازه‌های در حال اجرا"))
        proc_actions = QHBoxLayout()
        self.proc_count_label = QLabel("0 پردازه")
        self.proc_count_label.setObjectName("subtitle")
        proc_actions.addWidget(self.proc_count_label)
        proc_actions.addStretch()
        proc_refresh = QPushButton("به‌روزرسانی")
        proc_refresh.clicked.connect(self._refresh_procs)
        proc_actions.addWidget(proc_refresh)
        layout.addLayout(proc_actions)

        self.proc_table = QTableWidget(0, 5)
        self.proc_table.setHorizontalHeaderLabels(["PID", "PPID", "UID", "State", "Name"])
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.proc_table.verticalHeader().setVisible(False)
        self.proc_table.setAlternatingRowColors(True)
        layout.addWidget(self.proc_table, 1)

        layout.addWidget(make_section_title("اتصال‌های شبکه"))
        net_actions = QHBoxLayout()
        self.net_count_label = QLabel("0 اتصال")
        self.net_count_label.setObjectName("subtitle")
        net_actions.addWidget(self.net_count_label)
        net_actions.addStretch()
        net_refresh = QPushButton("به‌روزرسانی")
        net_refresh.clicked.connect(self._refresh_net)
        net_actions.addWidget(net_refresh)
        layout.addLayout(net_actions)

        self.net_table = QTableWidget(0, 4)
        self.net_table.setHorizontalHeaderLabels(["Proto", "Local", "Remote", "State"])
        self.net_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.net_table.verticalHeader().setVisible(False)
        self.net_table.setAlternatingRowColors(True)
        layout.addWidget(self.net_table, 1)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_all)
        self._timer.start(3000)

        QTimer.singleShot(200, self._refresh_all)

    def _refresh_all(self) -> None:
        self._refresh_procs()
        self._refresh_net()

    def _refresh_procs(self) -> None:
        try:
            procs = self._pm.list_processes()
        except Exception:
            return
        self.proc_table.setRowCount(0)
        for p in sorted(procs, key=lambda x: x.pid):
            row = self.proc_table.rowCount()
            self.proc_table.insertRow(row)
            self.proc_table.setItem(row, 0, QTableWidgetItem(str(p.pid)))
            self.proc_table.setItem(row, 1, QTableWidgetItem(str(p.ppid)))
            self.proc_table.setItem(row, 2, QTableWidgetItem(str(p.uid)))
            self.proc_table.setItem(row, 3, QTableWidgetItem(p.state))
            self.proc_table.setItem(row, 4, QTableWidgetItem(p.name))
        self.proc_count_label.setText(f"{len(procs)} پردازه")

    def _refresh_net(self) -> None:
        try:
            conns = self._nm.list_connections()
        except Exception:
            return
        self.net_table.setRowCount(0)
        for c in conns:
            row = self.net_table.rowCount()
            self.net_table.insertRow(row)
            self.net_table.setItem(row, 0, QTableWidgetItem(c.protocol))
            self.net_table.setItem(row, 1, QTableWidgetItem(f"{c.local_addr}:{c.local_port}"))
            self.net_table.setItem(row, 2, QTableWidgetItem(f"{c.remote_addr}:{c.remote_port}"))
            self.net_table.setItem(row, 3, QTableWidgetItem(c.state))
        self.net_count_label.setText(f"{len(conns)} اتصال")
