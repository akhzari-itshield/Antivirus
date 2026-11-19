"""Statistics tab."""

from __future__ import annotations
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget,
)

from itshield.gui.styles import get_palette
from itshield.gui.widgets import StatCard, make_section_title
from itshield.storage.database import Database


class StatsTab(QWidget):
    def __init__(self, db: Database, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._db = db

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = make_section_title("آمار و روند")
        title.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(title)

        actions = QHBoxLayout()
        actions.addStretch()
        refresh_btn = QPushButton("به‌روزرسانی")
        refresh_btn.clicked.connect(self._refresh)
        actions.addWidget(refresh_btn)
        layout.addLayout(actions)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_scans = StatCard("کل اسکن‌ها", "0")
        self.card_threats = StatCard("کل تهدیدات", "0")
        self.card_files = StatCard("فایل‌های اسکن‌شده", "0")
        self.card_quarantined = StatCard("قرنطینه‌شده", "0")
        for c in (self.card_scans, self.card_threats,
                  self.card_files, self.card_quarantined):
            cards.addWidget(c)
        layout.addLayout(cards)

        trend_title = make_section_title("روند تهدیدات")
        trend_title.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(trend_title)

        self.trend_chart = QTextEdit()
        self.trend_chart.setReadOnly(True)
        self.trend_chart.setObjectName("eventLog")
        self.trend_chart.setMaximumHeight(200)
        layout.addWidget(self.trend_chart)

        recent_title = make_section_title("اسکن‌های اخیر")
        recent_title.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(recent_title)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["تاریخ", "هدف", "وضعیت", "فایل‌ها", "مخرب", "مشکوک"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(10000)
        QTimer.singleShot(300, self._refresh)

    def _refresh(self) -> None:
        try:
            scans = self._db.fetchone("SELECT COUNT(*) AS c FROM scan_jobs")
            threats = self._db.fetchone(
                "SELECT COUNT(*) AS c FROM scan_results WHERE detection IN ('MALICIOUS','SUSPICIOUS')"
            )
            files = self._db.fetchone("SELECT COUNT(*) AS c FROM scan_results")
            quar = self._db.fetchone("SELECT COUNT(*) AS c FROM quarantine")
            self.card_scans.set_value(str(scans["c"] if scans else 0))
            self.card_threats.set_value(str(threats["c"] if threats else 0))
            self.card_files.set_value(str(files["c"] if files else 0))
            self.card_quarantined.set_value(str(quar["c"] if quar else 0))
            self._render_trend()
            self._render_recent()
        except Exception:
            pass

    def _render_trend(self) -> None:
        rows = self._db.fetchall(
            "SELECT DATE(started_at) AS day, "
            "SUM(files_malicious) AS mal, SUM(files_suspicious) AS susp "
            "FROM scan_jobs WHERE started_at IS NOT NULL AND started_at != '' "
            "GROUP BY DATE(started_at) ORDER BY day DESC LIMIT 14"
        )
        if not rows:
            self.trend_chart.setPlainText("هنوز داده‌ای برای نمایش وجود ندارد.")
            return
        max_count = 1
        per_day = []
        for r in rows:
            mal = int(r["mal"] or 0)
            susp = int(r["susp"] or 0)
            total = mal + susp
            per_day.append((r["day"], mal, susp, total))
            if total > max_count:
                max_count = total
        lines = []
        bar_width = 35
        for day, mal, susp, total in per_day:
            bar_len = int(bar_width * total / max(max_count, 1))
            bar = "\u2588" * bar_len + "\u2591" * (bar_width - bar_len)
            lines.append(f"{day:<12}  مخرب:{mal:>4}  مشکوک:{susp:>4}  {bar}")
        self.trend_chart.setPlainText("\n".join(lines))

    def _render_recent(self) -> None:
        p = get_palette()
        rows = self._db.fetchall(
            "SELECT started_at, target_path, state, files_scanned, "
            "files_malicious, files_suspicious "
            "FROM scan_jobs ORDER BY started_at DESC LIMIT 20"
        )
        self.table.setRowCount(0)
        from PySide6.QtGui import QColor
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(r["started_at"] or "")))
            self.table.setItem(row, 1, QTableWidgetItem(str(r["target_path"] or "")))
            state_item = QTableWidgetItem(str(r["state"] or ""))
            sc = {"COMPLETED": p.ok, "FAILED": p.err,
                  "CANCELLED": p.warn, "RUNNING": p.accent}
            state_item.setForeground(QColor(sc.get(str(r["state"] or ""), p.text)))
            self.table.setItem(row, 2, state_item)
            self.table.setItem(row, 3, QTableWidgetItem(str(r["files_scanned"] or 0)))
            mal_item = QTableWidgetItem(str(r["files_malicious"] or 0))
            if (r["files_malicious"] or 0) > 0:
                mal_item.setForeground(QColor(p.malicious))
                from PySide6.QtGui import QFont
                f = mal_item.font(); f.setBold(True); mal_item.setFont(f)
            self.table.setItem(row, 4, mal_item)
            susp_item = QTableWidgetItem(str(r["files_suspicious"] or 0))
            if (r["files_suspicious"] or 0) > 0:
                susp_item.setForeground(QColor(p.suspicious))
            self.table.setItem(row, 5, susp_item)
