"""Reusable widgets for the ITShield GUI (Phase 15 - refined).

Modern widgets with:
    * Gradient StatCards with hover elevation
    * Pulsing StatusDot with halo effect
    * PillLabel for status badges
    * SectionTitle with accent underline
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import (
    QColor, QFont, QPainter, QPaintEvent, QPen, QBrush,
    QRadialGradient, QLinearGradient,
)
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget,
)

from itshield.gui.styles import get_palette


class StatusDot(QWidget):
    """A colored circle with optional pulsing halo."""

    def __init__(
        self,
        color: str = "#7f849c",
        size: int = 12,
        pulsing: bool = False,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._color = QColor(color)
        self._size = size
        self._opacity = 1.0
        self._halo_opacity = 0.0
        self._pulse_increasing = False
        self.setFixedSize(size + 8, size + 8)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        if pulsing:
            self.start_pulsing()

    def set_color(self, color: str) -> None:
        self._color = QColor(color)
        self.update()

    def start_pulsing(self) -> None:
        if not self._timer.isActive():
            self._timer.start(60)

    def stop_pulsing(self) -> None:
        self._timer.stop()
        self._opacity = 1.0
        self._halo_opacity = 0.0
        self.update()

    def _tick(self) -> None:
        step = 0.04
        if self._pulse_increasing:
            self._halo_opacity += step
            if self._halo_opacity >= 0.6:
                self._halo_opacity = 0.6
                self._pulse_increasing = False
        else:
            self._halo_opacity -= step
            if self._halo_opacity <= 0.0:
                self._halo_opacity = 0.0
                self._pulse_increasing = True
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        center_x = self.width() // 2
        center_y = self.height() // 2

        if self._timer.isActive() and self._halo_opacity > 0:
            halo = QColor(self._color)
            halo.setAlphaF(self._halo_opacity * 0.4)
            p.setPen(QPen(Qt.PenStyle.NoPen))
            p.setBrush(QBrush(halo))
            halo_size = self._size + int(self._halo_opacity * 8)
            p.drawEllipse(center_x - halo_size // 2,
                          center_y - halo_size // 2,
                          halo_size, halo_size)

        color = QColor(self._color)
        p.setPen(QPen(Qt.PenStyle.NoPen))
        p.setBrush(QBrush(color))
        p.drawEllipse(center_x - self._size // 2,
                      center_y - self._size // 2,
                      self._size, self._size)


class StatusIndicator(QWidget):
    """A labeled status row: [dot] [label] [value]."""

    def __init__(self, label: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._dot = StatusDot()
        self._label = QLabel(label)
        self._label.setObjectName("subtitle")
        self._value = QLabel("—")
        f = self._value.font()
        f.setBold(True)
        f.setPointSize(11)
        self._value.setFont(f)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self._dot)
        layout.addWidget(self._label)
        layout.addWidget(self._value, 1)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    def set_state(self, value: str, color: str, pulsing: bool = False) -> None:
        self._value.setText(value)
        self._dot.set_color(color)
        if pulsing:
            self._dot.start_pulsing()
        else:
            self._dot.stop_pulsing()


class StatCard(QFrame):
    """A boxed stat with big value, small label, and optional icon row."""

    def __init__(
        self,
        label: str,
        value: str = "0",
        color: Optional[str] = None,
        icon: str = "",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setMinimumHeight(110)

        self._value_label = QLabel(value)
        self._value_label.setObjectName("stat_value")
        if color:
            self._value_label.setStyleSheet(f"color: {color};")
        self._label_label = QLabel(label)
        self._label_label.setObjectName("stat_label")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)
        layout.addWidget(self._value_label)
        layout.addWidget(self._label_label)
        layout.addStretch()

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)

    def set_color(self, color: str) -> None:
        self._value_label.setStyleSheet(f"color: {color};")


class PillLabel(QLabel):
    """A rounded status badge."""

    def __init__(
        self,
        text: str = "",
        color: Optional[str] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(text, parent)
        p = get_palette()
        bg = color or p.bg_card
        fg = p.text
        self.setStyleSheet(f"""
            background-color: {bg};
            color: {fg};
            padding: 3px 12px;
            border-radius: 11px;
            font-size: 11px;
            font-weight: 600;
        """)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedHeight(24)

    def set_colors(self, bg: str, fg: str) -> None:
        self.setStyleSheet(f"""
            background-color: {bg};
            color: {fg};
            padding: 3px 12px;
            border-radius: 11px;
            font-size: 11px;
            font-weight: 600;
        """)


def verdict_color(verdict: str) -> str:
    p = get_palette()
    return {
        "CLEAN": p.clean,
        "UNKNOWN": p.unknown,
        "SUSPICIOUS": p.suspicious,
        "MALICIOUS": p.malicious,
        "SKIPPED": p.skipped,
    }.get(verdict, p.text)


def severity_color(severity: str) -> str:
    p = get_palette()
    return {
        "LOW": p.sev_low,
        "MEDIUM": p.sev_medium,
        "HIGH": p.sev_high,
        "CRITICAL": p.sev_critical,
    }.get(severity, p.text)


def state_color(state: str) -> str:
    p = get_palette()
    return {
        "RUNNING": p.ok,
        "STOPPED": p.text_muted,
        "STARTING": p.warn,
        "STOPPING": p.warn,
        "DEGRADED": p.warn,
        "FAILED": p.err,
    }.get(state, p.text_muted)


def make_section_title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("title")
    return label


def make_subtitle(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("subtitle")
    return label
