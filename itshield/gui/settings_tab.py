"""Settings tab - configure paths, theme and limits."""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from itshield.config.settings import Settings, get_settings
from itshield.gui.styles import get_palette, set_theme
from itshield.gui.widgets import make_section_title


class SettingsTab(QWidget):
    """Configuration tab."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        s = get_settings()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(make_section_title("تنظیمات"))

        form = QFormLayout()

        sig_row = QHBoxLayout()
        self.sig_edit = QLineEdit(str(s.signature_bank_path))
        sig_row.addWidget(self.sig_edit, 1)
        sig_btn = QPushButton("...")
        sig_btn.clicked.connect(lambda: self._pick_file(self.sig_edit))
        sig_row.addWidget(sig_btn)
        form.addRow("بانک امضا:", self._wrap(sig_row))

        yara_row = QHBoxLayout()
        self.yara_edit = QLineEdit(str(s.yara_rules_path))
        yara_row.addWidget(self.yara_edit, 1)
        yara_btn = QPushButton("...")
        yara_btn.clicked.connect(lambda: self._pick_file(self.yara_edit))
        yara_row.addWidget(yara_btn)
        form.addRow("قواعد YARA:", self._wrap(yara_row))

        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 4096)
        self.max_size_spin.setValue(s.scanner_max_file_size // (1024 * 1024))
        form.addRow("حداکثر حجم فایل (MiB):", self.max_size_spin)

        self.yara_timeout_spin = QSpinBox()
        self.yara_timeout_spin.setRange(1, 300)
        self.yara_timeout_spin.setValue(s.scanner_yara_timeout_seconds)
        form.addRow("YARA timeout (ثانیه):", self.yara_timeout_spin)

        self.theme_combo = QComboBox()
        self.theme_combo.addItem("تیره", "dark")
        self.theme_combo.addItem("روشن", "light")
        self.theme_combo.setCurrentIndex(0 if get_palette().name == "dark" else 1)
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        form.addRow("پوسته:", self.theme_combo)

        layout.addLayout(form)
        layout.addStretch()

        save_row = QHBoxLayout()
        save_row.addStretch()
        save_btn = QPushButton("ذخیره تنظیمات")
        save_btn.setObjectName("primary")
        save_btn.clicked.connect(self._save)
        save_row.addWidget(save_btn)
        layout.addLayout(save_row)

        self._status_label = QLabel("")
        self._status_label.setObjectName("subtitle")
        layout.addWidget(self._status_label)

    @staticmethod
    def _wrap(layout: QHBoxLayout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        return w

    def _pick_file(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب فایل")
        if path:
            edit.setText(path)

    def _on_theme_changed(self) -> None:
        name = self.theme_combo.currentData()
        set_theme(name)

    def _save(self) -> None:
        s = get_settings()
        s.signature_bank_path = type(s.signature_bank_path)(self.sig_edit.text())
        s.yara_rules_path = type(s.yara_rules_path)(self.yara_edit.text())
        s.scanner_max_file_size = self.max_size_spin.value() * 1024 * 1024
        s.scanner_yara_timeout_seconds = self.yara_timeout_spin.value()
        self._status_label.setText("تنظیمات ذخیره شد. برای اعمال کامل، برنامه را مجدداً راه‌اندازی کنید.")
