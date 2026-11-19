"""Scan tab - manual file/directory scanning UI."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from itshield.gui.gui_worker import BackgroundBridge, BackgroundEvent
from itshield.gui.styles import get_palette
from itshield.gui.widgets import make_section_title, verdict_color
from itshield.scanner.models import (
    DetectionVerdict,
    FileResult,
    ScanProgress,
    ScanRequest,
)
from itshield.scanner.scanner import FileScanner


class ScanTab(QWidget):
    """Manual scan tab: pick a path, run scan, view results."""

    def __init__(
        self,
        scanner: FileScanner,
        bridge: BackgroundBridge,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._scanner = scanner
        self._bridge = bridge
        self._worker: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()
        self._results: list[FileResult] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(make_section_title("اسکن دستی"))

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("مسیر:"))
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("یک فایل یا پوشه برای اسکن انتخاب کنید...")
        path_row.addWidget(self.path_edit, 1)
        browse_file_btn = QPushButton("انتخاب فایل")
        browse_file_btn.clicked.connect(self._browse_file)
        path_row.addWidget(browse_file_btn)
        browse_dir_btn = QPushButton("انتخاب پوشه")
        browse_dir_btn.clicked.connect(self._browse_dir)
        path_row.addWidget(browse_dir_btn)
        layout.addLayout(path_row)

        opts_row = QHBoxLayout()
        self.recursive_check = QCheckBox("بازگشتی")
        self.recursive_check.setChecked(True)
        opts_row.addWidget(self.recursive_check)
        opts_row.addSpacing(16)
        opts_row.addWidget(QLabel("حداکثر حجم فایل (MiB):"))
        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 4096)
        self.max_size_spin.setValue(256)
        opts_row.addWidget(self.max_size_spin)
        opts_row.addStretch()
        self.scan_btn = QPushButton("شروع اسکن")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self._start_scan)
        opts_row.addWidget(self.scan_btn)
        self.cancel_btn = QPushButton("لغو")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_scan)
        opts_row.addWidget(self.cancel_btn)
        layout.addLayout(opts_row)

        prog_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        prog_row.addWidget(self.progress_bar, 1)
        self.progress_label = QLabel("آماده")
        prog_row.addWidget(self.progress_label)
        layout.addLayout(prog_row)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["فایل", "نوع", "حجم", "SHA-256", "Verdict", "دلیل"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)

        self._bridge.subscribe("scan_progress", self._on_progress)
        self._bridge.subscribe("scan_result", self._on_result)
        self._bridge.subscribe("scan_done", self._on_done)

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب فایل")
        if path:
            self.path_edit.setText(path)

    def _browse_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "انتخاب پوشه")
        if path:
            self.path_edit.setText(path)

    def _start_scan(self) -> None:
        path = self.path_edit.text().strip()
        if not path:
            return
        target = Path(path).expanduser().resolve()
        if not target.exists():
            return

        self.table.setRowCount(0)
        self._results.clear()
        self._cancel_event.clear()
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.progress_label.setText("شروع اسکن...")

        request = ScanRequest.from_path(
            target,
            recursive=self.recursive_check.isChecked(),
            max_file_size=self.max_size_spin.value() * 1024 * 1024,
        )

        self._worker = threading.Thread(
            target=self._scan_worker,
            args=(request,),
            daemon=True,
            name="gui-scan",
        )
        self._worker.start()

    def _cancel_scan(self) -> None:
        self._cancel_event.set()
        self.cancel_btn.setEnabled(False)
        self.progress_label.setText("در حال لغو...")

    def _scan_worker(self, request: ScanRequest) -> None:
        """Background worker: runs the scan and emits events to the bridge."""
        try:
            scanner = self._scanner
            file_list = list(scanner._iter_files(Path(request.target_path)))
            total = len(file_list)
            scanned = 0
            started = time.time()

            def emit_progress(p: ScanProgress) -> None:
                self._bridge.emit(BackgroundEvent(
                    kind="scan_progress",
                    data={
                        "files_total": p.files_total,
                        "files_scanned": p.files_scanned,
                        "current_path": p.current_path,
                        "percent": p.percent,
                    },
                ))

            for fpath in file_list:
                if self._cancel_event.is_set():
                    break
                try:
                    r = scanner.scan_file(fpath)
                except Exception as exc:
                    r = FileResult(
                        file_path=str(fpath),
                        verdict=DetectionVerdict.SKIPPED,
                        reason=f"error: {exc}",
                    )
                scanned += 1
                self._bridge.emit(BackgroundEvent(
                    kind="scan_result",
                    data={
                        "file_path": r.file_path,
                        "file_size": r.file_size,
                        "file_type": r.file_type,
                        "sha256": r.sha256,
                        "verdict": r.verdict.value,
                        "matched_signature": r.matched_signature,
                        "matched_yara_rules": r.matched_yara_rules,
                        "reason": r.reason,
                    },
                ))
                emit_progress(ScanProgress(
                    job_id=request.job_id,
                    files_total=total,
                    files_scanned=scanned,
                    current_path=str(fpath),
                    bytes_processed=r.file_size,
                    percent=round(100.0 * scanned / max(total, 1), 2),
                ))

            duration = round(time.time() - started, 3)
            self._bridge.emit(BackgroundEvent(
                kind="scan_done",
                data={
                    "files_total": total,
                    "files_scanned": scanned,
                    "duration_seconds": duration,
                    "cancelled": self._cancel_event.is_set(),
                },
            ))
        except Exception as exc:
            self._bridge.emit(BackgroundEvent(
                kind="scan_done",
                data={"error": str(exc), "cancelled": True},
            ))

    def _on_progress(self, event: BackgroundEvent) -> None:
        d = event.data
        self.progress_bar.setValue(int(d.get("percent", 0)))
        cur = d.get("current_path", "")
        name = Path(cur).name if cur else ""
        self.progress_label.setText(
            f"{d.get('percent', 0):.1f}%  ({d.get('files_scanned', 0)}/{d.get('files_total', 0)})  {name[:40]}"
        )

    def _on_result(self, event: BackgroundEvent) -> None:
        d = event.data
        verdict = d.get("verdict", "UNKNOWN")
        row = self.table.rowCount()
        self.table.insertRow(row)
        p = get_palette()
        color = verdict_color(verdict)
        cells = [
            Path(d.get("file_path", "")).name,
            d.get("file_type") or "",
            str(d.get("file_size", 0)),
            (d.get("sha256") or "")[:16],
            verdict,
            d.get("reason", ""),
        ]
        for col, text in enumerate(cells):
            item = QTableWidgetItem(text)
            if col == 4:
                item.setForeground(Qt.GlobalColor.white) if False else None
                from PySide6.QtGui import QColor
                item.setForeground(QColor(color))
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            self.table.setItem(row, col, item)

    def _on_done(self, event: BackgroundEvent) -> None:
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        if event.data.get("error"):
            self.progress_label.setText(f"خطا: {event.data['error']}")
        elif event.data.get("cancelled"):
            self.progress_label.setText("اسکن لغو شد")
        else:
            self.progress_label.setText(
                f"تکمیل شد: {event.data.get('files_scanned', 0)}/{event.data.get('files_total', 0)} "
                f"فایل در {event.data.get('duration_seconds', 0)}s"
            )
