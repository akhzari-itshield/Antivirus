"""Quarantine tab - list/restore/delete quarantined files."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from itshield.gui.styles import get_palette
from itshield.gui.widgets import make_section_title
from itshield.quarantine.engine import QuarantineEngine


class QuarantineTab(QWidget):
    """Quarantine management tab."""

    def __init__(
        self,
        quarantine: QuarantineEngine,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._q = quarantine

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(make_section_title("قرنطینه"))
        sub = QLabel("فایل‌های قرنطینه‌شده — امکان بازیابی یا حذف دائمی")
        sub.setObjectName("subtitle")
        layout.addWidget(sub)

        actions = QHBoxLayout()
        actions.addStretch()
        refresh_btn = QPushButton("به‌روزرسانی")
        refresh_btn.clicked.connect(self.refresh)
        actions.addWidget(refresh_btn)
        self.restore_btn = QPushButton("بازیابی...")
        self.restore_btn.clicked.connect(self._restore_selected)
        actions.addWidget(self.restore_btn)
        self.delete_btn = QPushButton("حذف دائمی")
        self.delete_btn.setObjectName("danger")
        self.delete_btn.clicked.connect(self._delete_selected)
        actions.addWidget(self.delete_btn)
        layout.addLayout(actions)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "SHA-256", "حجم", "مسیر اصلی", "زمان قرنطینه"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        layout.addWidget(self.table, 1)

        self.details = QLabel("")
        self.details.setWordWrap(True)
        self.details.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.details.setStyleSheet(
            f"background-color: {get_palette().bg_alt};"
            f"border: 1px solid {get_palette().border};"
            "border-radius: 4px; padding: 8px; min-height: 80px;"
            "font-family: 'Monospace';"
        )
        layout.addWidget(self.details)

    def refresh(self) -> None:
        """Reload the quarantine list from the database."""
        self.table.setRowCount(0)
        try:
            entries = self._q.list_quarantined()
        except Exception as exc:
            self.details.setText(f"خطا در بارگذاری قرنطینه: {exc}")
            return
        for e in entries:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(e["id"])))
            self.table.setItem(row, 1, QTableWidgetItem((e["sha256"] or "")[:16]))
            self.table.setItem(row, 2, QTableWidgetItem(str(e["size"] or 0)))
            self.table.setItem(row, 3, QTableWidgetItem(e["original_path"] or ""))
            self.table.setItem(row, 4, QTableWidgetItem(e["quarantined_at"] or ""))
        if not entries:
            self.details.setText("هیچ فایلی در قرنطینه نیست.")

    def _selected_id(self) -> Optional[int]:
        items = self.table.selectedItems()
        if not items:
            return None
        row = items[0].row()
        try:
            return int(self.table.item(row, 0).text())
        except (ValueError, AttributeError):
            return None

    def _restore_selected(self) -> None:
        row_id = self._selected_id()
        if row_id is None:
            QMessageBox.information(self, "انتخاب نشده", "ابتدا یک سطر انتخاب کنید.")
            return
        target, _ = QFileDialog.getSaveFileName(self, "محل بازیابی")
        if not target:
            return
        try:
            result = self._q.restore(row_id, target)
            QMessageBox.information(
                self, "بازیابی شد",
                f"فایل به {result['restored_to']} بازیابی شد.\nSHA-256: {result['sha256'][:16]}..."
            )
            self.refresh()
        except Exception as exc:
            QMessageBox.critical(self, "خطا در بازیابی", str(exc))

    def _delete_selected(self) -> None:
        row_id = self._selected_id()
        if row_id is None:
            QMessageBox.information(self, "انتخاب نشده", "ابتدا یک سطر انتخاب کنید.")
            return
        confirm = QMessageBox.question(
            self, "تأیید حذف دائمی",
            "این عمل فایل را برای همیشه حذف می‌کند. ادامه می‌دهید؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            self._q.delete_permanent(row_id)
            self.refresh()
        except Exception as exc:
            QMessageBox.critical(self, "خطا در حذف", str(exc))
