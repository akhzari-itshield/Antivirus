"""Incidents tab - browse and resolve security incidents (Phase 7)."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from itshield.gui.styles import get_palette
from itshield.gui.widgets import make_section_title, severity_color
from itshield.incidents.manager import (
    IncidentManager,
    IncidentState,
)


class IncidentsTab(QWidget):
    """List + manage security incidents."""

    def __init__(
        self,
        manager: IncidentManager,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._mgr = manager

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(make_section_title("رخدادهای امنیتی"))
        sub = QLabel("رخدادهای شناسایی‌شده توسط Correlation Engine و Behavior Analyzer")
        sub.setObjectName("subtitle")
        layout.addWidget(sub)

        actions = QHBoxLayout()
        actions.addStretch()
        refresh_btn = QPushButton("به‌روزرسانی")
        refresh_btn.clicked.connect(self.refresh)
        actions.addWidget(refresh_btn)
        self.investigate_btn = QPushButton("در حال بررسی")
        self.investigate_btn.clicked.connect(self._investigate)
        actions.addWidget(self.investigate_btn)
        self.resolve_btn = QPushButton("حل‌شده")
        self.resolve_btn.clicked.connect(self._resolve)
        actions.addWidget(self.resolve_btn)
        self.dismiss_btn = QPushButton("رد شد")
        self.dismiss_btn.clicked.connect(self._dismiss)
        actions.addWidget(self.dismiss_btn)
        layout.addLayout(actions)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["ID", "Severity", "State", "Title", "Created at"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self.table, 1)

        layout.addWidget(QLabel("جزئیات:"))
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(150)
        layout.addWidget(self.details)

    def refresh(self) -> None:
        try:
            incidents = self._mgr.list_incidents(limit=200)
        except Exception as exc:
            self.details.setPlainText(f"خطا در بارگذاری رخدادها: {exc}")
            return
        self.table.setRowCount(0)
        for inc in incidents:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(inc["id"][:8]))
            sev = inc["severity"]
            sev_item = QTableWidgetItem(sev)
            from PySide6.QtGui import QColor
            sev_item.setForeground(QColor(severity_color(sev)))
            f = sev_item.font()
            f.setBold(True)
            sev_item.setFont(f)
            self.table.setItem(row, 1, sev_item)
            self.table.setItem(row, 2, QTableWidgetItem(inc["state"]))
            self.table.setItem(row, 3, QTableWidgetItem(inc.get("title") or ""))
            self.table.setItem(row, 4, QTableWidgetItem(inc["created_at"]))

    def _selected_id(self) -> Optional[str]:
        items = self.table.selectedItems()
        if not items:
            return None
        row = items[0].row()
        short = self.table.item(row, 0).text()
        try:
            incidents = self._mgr.list_incidents(limit=200)
        except Exception:
            return None
        for inc in incidents:
            if inc["id"].startswith(short):
                return inc["id"]
        return None

    def _on_selection_changed(self) -> None:
        inc_id = self._selected_id()
        if inc_id is None:
            self.details.setPlainText("")
            return
        inc = self._mgr.get(inc_id)
        if inc is None:
            return
        text = (
            f"Title:    {inc.get('title','')}\n"
            f"Severity: {inc.get('severity','')}\n"
            f"State:    {inc.get('state','')}\n"
            f"Created:  {inc.get('created_at','')}\n\n"
            f"Summary:\n{inc.get('summary','')}\n\n"
            f"Linked events: {len(inc.get('linked_events', []))}"
        )
        self.details.setPlainText(text)

    def _investigate(self) -> None:
        inc_id = self._selected_id()
        if inc_id is None:
            return
        if self._mgr.start_investigating(inc_id):
            self.refresh()

    def _resolve(self) -> None:
        inc_id = self._selected_id()
        if inc_id is None:
            return
        if QMessageBox.question(self, "تأیید", "رخداد به‌عنوان حل‌شده علامت بخورد؟") == QMessageBox.StandardButton.Yes:
            if self._mgr.resolve(inc_id):
                self.refresh()

    def _dismiss(self) -> None:
        inc_id = self._selected_id()
        if inc_id is None:
            return
        if QMessageBox.question(self, "تأیید", "رخداد رد شود؟") == QMessageBox.StandardButton.Yes:
            if self._mgr.dismiss(inc_id):
                self.refresh()
