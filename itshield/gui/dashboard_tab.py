"""Dashboard tab."""

from __future__ import annotations
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton,
    QVBoxLayout, QWidget,
)

from itshield.gui.styles import get_palette
from itshield.gui.widgets import (
    StatCard, StatusDot, StatusIndicator,
    make_section_title, make_subtitle, state_color,
)


class DashboardTab(QWidget):
    refresh_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = make_section_title("داشبورد")
        title.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(title)

        status_row = QHBoxLayout()
        status_row.setSpacing(24)
        self.core_status = StatusIndicator("Core:")
        self.protection_status = StatusIndicator("حفاظت:")
        self.signature_count = StatusIndicator("امضاها:")
        self.yara_count = StatusIndicator("قواعد YARA:")
        for w in (self.core_status, self.protection_status,
                  self.signature_count, self.yara_count):
            status_row.addWidget(w)
        status_row.addStretch()
        layout.addLayout(status_row)

        cards_row = QGridLayout()
        cards_row.setSpacing(12)
        self.card_scanned = StatCard("فایل‌های اسکن‌شده", "0")
        self.card_threats = StatCard("تهدیدات", "0")
        self.card_quarantined = StatCard("قرنطینه‌شده", "0")
        self.card_incidents = StatCard("رخدادهای باز", "0")
        cards_row.addWidget(self.card_scanned, 0, 0)
        cards_row.addWidget(self.card_threats, 0, 1)
        cards_row.addWidget(self.card_quarantined, 0, 2)
        cards_row.addWidget(self.card_incidents, 0, 3)
        layout.addLayout(cards_row)

        act_title = make_section_title("فعالیت اخیر")
        act_title.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(act_title)

        self.activity_label = QLabel("هنوز رویدادی ثبت نشده است.")
        self.activity_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)
        self.activity_label.setStyleSheet(
            f"background-color: {get_palette().bg_alt};"
            f"border: 1px solid {get_palette().border};"
            "border-radius: 8px; padding: 16px; min-height: 180px;"
            "font-family: 'Vazirmatn', monospace; font-size: 12px;"
        )
        self.activity_label.setWordWrap(True)
        layout.addWidget(self.activity_label, 1)

        layout.addStretch()

    def update_core_status(self, state: str) -> None:
        self.core_status.set_state(state, state_color(state),
                                   pulsing=(state == "RUNNING"))

    def update_protection_status(self, enabled: bool) -> None:
        p = get_palette()
        self.protection_status.set_state(
            "فعال" if enabled else "غیرفعال",
            p.ok if enabled else p.text_muted,
            pulsing=enabled,
        )

    def update_engine_counts(self, sigs: int, yara: int) -> None:
        p = get_palette()
        self.signature_count.set_state(str(sigs), p.accent)
        self.yara_count.set_state(str(yara), p.accent)

    def update_stats(self, scanned: int, threats: int,
                     quarantined: int, incidents: int) -> None:
        p = get_palette()
        self.card_scanned.set_value(str(scanned))
        self.card_threats.set_value(str(threats))
        self.card_quarantined.set_value(str(quarantined))
        self.card_incidents.set_value(str(incidents))
        if threats > 0:
            self.card_threats.set_color(p.malicious)
        if incidents > 0:
            self.card_incidents.set_color(p.sev_high)

    def append_activity(self, line: str) -> None:
        current = self.activity_label.text()
        lines = current.split("\n") if current and "رویدادی" not in current else []
        p = get_palette()
        if "[THREAT]" in line or "[MALICIOUS]" in line:
            line = f'<span style="color:{p.malicious}">{line}</span>'
        elif "[SUSPICIOUS]" in line or "[ALERT]" in line:
            line = f'<span style="color:{p.suspicious}">{line}</span>'
        elif "[scan]" in line:
            line = f'<span style="color:{p.info}">{line}</span>'
        lines.insert(0, line)
        lines = lines[:50]
        self.activity_label.setText("<br>".join(lines))
        self.activity_label.setTextFormat(Qt.TextFormat.RichText)
