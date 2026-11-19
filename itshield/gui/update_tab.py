"""Update tab - YARA rule download from 12 sources."""

from __future__ import annotations
import threading
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QMessageBox, QPushButton,
    QScrollArea, QTextEdit, QVBoxLayout, QWidget,
)

from itshield.gui.gui_worker import BackgroundBridge, BackgroundEvent
from itshield.gui.styles import get_palette
from itshield.gui.widgets import make_section_title
from itshield.update.yara_sources import YARA_SOURCES
from itshield.update.http_source import GitHubArchiveSource
from itshield.update.yara_downloader import YaraRuleDownloader


class UpdateTab(QWidget):
    def __init__(
        self,
        update_manager=None,
        yara_downloader: Optional[YaraRuleDownloader] = None,
        hash_downloader=None,
        bridge: Optional[BackgroundBridge] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._yara_dl = yara_downloader
        self._bridge = bridge
        self._source_checks: dict[str, QCheckBox] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = make_section_title("دانلود قواعد YARA")
        title.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(title)

        subtitle = QLabel("۱۲ منبع منتخب — تیک بزنید و دانلود کنید")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(subtitle)

        sources_scroll = QScrollArea()
        sources_scroll.setWidgetResizable(True)
        sources_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        sources_widget = QWidget()
        sources_layout = QVBoxLayout(sources_widget)
        sources_layout.setContentsMargins(0, 0, 0, 0)
        sources_layout.setSpacing(6)

        for src in YARA_SOURCES:
            cb = QCheckBox(f"{src.name} ({src.repo})")
            cb.setChecked(True)
            self._source_checks[src.key] = cb
            sources_layout.addWidget(cb)

        sources_layout.addStretch()
        sources_scroll.setWidget(sources_widget)
        sources_scroll.setMaximumHeight(250)
        layout.addWidget(sources_scroll)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.download_btn = QPushButton("دانلود انتخاب‌شده‌ها")
        self.download_btn.setObjectName("primary")
        self.download_btn.clicked.connect(self._download_selected)
        btn_row.addWidget(self.download_btn)

        self.list_btn = QPushButton("فهرست قواعد")
        self.list_btn.clicked.connect(self._list_rules)
        btn_row.addWidget(self.list_btn)

        self.clear_btn = QPushButton("پاک‌سازی")
        self.clear_btn.clicked.connect(self._clear_rules)
        btn_row.addWidget(self.clear_btn)
        layout.addLayout(btn_row)

        self.status_label = QLabel("آماده")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)
        self.status_label.setStyleSheet(
            f"background-color: {get_palette().bg_card};"
            f"border: 1px solid {get_palette().border};"
            "border-radius: 8px; padding: 16px; min-height: 60px;"
        )
        layout.addWidget(self.status_label, 1)

        hist_title = make_section_title("تاریخچه")
        hist_title.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(hist_title)

        self.history = QTextEdit()
        self.history.setReadOnly(True)
        self.history.setObjectName("eventLog")
        self.history.setMaximumHeight(100)
        layout.addWidget(self.history)

        if self._bridge is not None:
            self._bridge.subscribe("yara_download_done", self._on_done)

        self._refresh_history()

    def _refresh_history(self) -> None:
        if self._yara_dl is None:
            self.history.setPlainText("هنوز به‌روزرسانی ثبت نشده است.")
            return
        try:
            rows = self._yara_dl._db.fetchall(
                "SELECT applied_at, status, details "
                "FROM update_history ORDER BY applied_at DESC LIMIT 20"
            )
            if not rows:
                self.history.setPlainText("هنوز به‌روزرسانی ثبت نشده است.")
                return
            lines = []
            for r in rows:
                lines.append(f"{r['applied_at'][:19]}  [{r['status']}]  {r['details'][:80]}")
            self.history.setPlainText("\n".join(lines))
        except Exception:
            self.history.setPlainText("خطا در بارگذاری تاریخچه")

    def _download_selected(self) -> None:
        if self._yara_dl is None:
            return
        selected = [s for s in YARA_SOURCES if self._source_checks[s.key].isChecked()]
        if not selected:
            QMessageBox.information(self, "هیچ", "هیچ منبعی انتخاب نشده است.")
            return
        confirm = QMessageBox.question(
            self, "تأیید",
            f"از {len(selected)} منبع دانلود شود؟",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.download_btn.setEnabled(False)
        self.status_label.setText("در حال دانلود...")

        def _worker():
            total = 0
            errors = []
            for src in selected:
                try:
                    dl = YaraRuleDownloader(
                        db=self._yara_dl._db,
                        rules_dir=self._yara_dl.rules_dir,
                        github_source=GitHubArchiveSource(repo=src.repo, ref=src.ref),
                        file_prefix=src.effective_prefix,
                        subdirs=src.subdirs,
                    )
                    result = dl.download_and_merge()
                    if result.success:
                        total += result.rules_downloaded
                    else:
                        errors.append(f"{src.name}: {result.status}")
                except Exception as exc:
                    errors.append(f"{src.name}: {exc}")

            if self._bridge is not None:
                self._bridge.emit(BackgroundEvent(
                    kind="yara_download_done",
                    data={
                        "success": total > 0,
                        "rules_downloaded": total,
                        "errors": errors[:5],
                        "count": len(selected),
                    },
                ))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_done(self, event: BackgroundEvent) -> None:
        d = event.data
        self.download_btn.setEnabled(True)
        if d.get("success"):
            self.status_label.setText(
                f"موفق: {d.get('rules_downloaded', 0)} فایل قاعده از "
                f"{d.get('count', 0)} منبع دانلود شد.\n"
                f"برای فعال‌شدن، برنامه را ری‌استارت کنید."
            )
            QMessageBox.information(
                self, "موفق",
                f"{d.get('rules_downloaded', 0)} فایل قاعده دانلود شد.\n"
                f"برنامه را ری‌استارت کنید.",
            )
        else:
            errs = d.get("errors", [])
            self.status_label.setText(
                f"ناموفق\n" + "\n".join(f"  - {e}" for e in errs[:3])
            )
        self._refresh_history()

    def _list_rules(self) -> None:
        if self._yara_dl is None:
            return
        all_files = []
        for src in YARA_SOURCES:
            dl = YaraRuleDownloader(
                db=self._yara_dl._db,
                rules_dir=self._yara_dl.rules_dir,
                github_source=GitHubArchiveSource(repo=src.repo, ref=src.ref),
                file_prefix=src.effective_prefix,
            )
            all_files.extend(dl.list_downloaded_rules())
        if not all_files:
            self.status_label.setText("هنوز فایل قاعده‌ای دانلود نشده است.")
            return
        lines = [f"{len(all_files)} فایل قاعده:"]
        for r in all_files[:15]:
            lines.append(f"  {r['filename']}  ({r['size']} bytes)")
        if len(all_files) > 15:
            lines.append(f"  ... و {len(all_files) - 15} فایل دیگر")
        self.status_label.setText("\n".join(lines))

    def _clear_rules(self) -> None:
        if self._yara_dl is None:
            return
        confirm = QMessageBox.question(
            self, "تأیید", "همه قواعد پاک شوند؟ (sample.yar حفظ می‌شود)")
        if confirm != QMessageBox.StandardButton.Yes:
            return
        total = 0
        for src in YARA_SOURCES:
            dl = YaraRuleDownloader(
                db=self._yara_dl._db,
                rules_dir=self._yara_dl.rules_dir,
                github_source=GitHubArchiveSource(repo=src.repo, ref=src.ref),
                file_prefix=src.effective_prefix,
            )
            total += dl.clear_downloaded_rules()
        self.status_label.setText(f"{total} فایل پاک شد.")
