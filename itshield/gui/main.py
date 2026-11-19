"""ITShield GUI entry point (PySide6).

Sidebar navigation design with emerald green accent.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal, QSize
from PySide6.QtGui import (
    QAction, QColor, QFont, QIcon, QKeySequence,
    QPainter, QPen, QBrush, QPainterPath, QPixmap,
)
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QMainWindow, QMenu, QMessageBox, QPushButton, QScrollArea,
    QStackedWidget, QStatusBar, QSystemTrayIcon, QVBoxLayout,
    QWidget, QSizePolicy,
)

from itshield.config.settings import get_settings
from itshield.logging.logger import init_logging, get_logger
from itshield.scanner.file_analyzer import FileAnalyzer
from itshield.scanner.hash_engine import HashEngine
from itshield.scanner.scanner import FileScanner
from itshield.scanner.signature_engine import SignatureEngine
from itshield.scanner.yara_engine import YaraEngine
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.events.bus import EventBus
from itshield.quarantine.engine import QuarantineEngine
from itshield.incidents.manager import IncidentManager
from itshield.update.update_manager import UpdateManager
from itshield.update.yara_downloader import YaraRuleDownloader

from itshield.gui.styles import set_theme, get_palette
from itshield.gui.gui_worker import BackgroundBridge
from itshield.gui.widgets import StatusDot

from itshield.gui.dashboard_tab import DashboardTab
from itshield.gui.scan_tab import ScanTab
from itshield.gui.realtime_tab import RealtimeTab
from itshield.gui.quarantine_tab import QuarantineTab
from itshield.gui.events_tab import EventsTab
from itshield.gui.system_tab import SystemTab
from itshield.gui.incidents_tab import IncidentsTab
from itshield.gui.update_tab import UpdateTab
from itshield.gui.stats_tab import StatsTab
from itshield.gui.settings_tab import SettingsTab

init_logging()
logger = get_logger("gui")

NAV_ITEMS = [
    ("داشبورد", 0),
    ("اسکن", 1),
    ("حفاظت زنده", 2),
    ("قرنطینه", 3),
    ("رویدادها", 4),
    ("سیستم", 5),
    ("رخدادها", 6),
    ("به‌روزرسانی", 7),
    ("آمار و روند", 8),
    ("تنظیمات", 9),
]


class NavButton(QPushButton):
    """A sidebar navigation button with active/inactive states."""

    def __init__(self, label: str, index: int, parent=None):
        super().__init__(label, parent)
        self._index = index
        self._active = False
        self.setCheckable(True)
        self.setMinimumHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setObjectName("navButton")
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

    @property
    def index(self) -> int:
        return self._index

    def set_active(self, active: bool) -> None:
        self._active = active
        self.setChecked(active)
        self.style().unpolish(self)
        self.style().polish(self)


class Sidebar(QWidget):
    """Left navigation sidebar."""

    page_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(240)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        logo_frame = QFrame()
        logo_frame.setObjectName("sidebarLogo")
        logo_frame.setFixedHeight(64)
        logo_layout = QHBoxLayout(logo_frame)
        logo_layout.setContentsMargins(20, 0, 20, 0)
        title = QLabel("ITShield")
        title.setObjectName("sidebarTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        logo_layout.addWidget(title)
        logo_layout.addStretch()
        layout.addWidget(logo_frame)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setObjectName("separator")
        layout.addWidget(sep)

        nav_container = QWidget()
        nav_layout = QVBoxLayout(nav_container)
        nav_layout.setContentsMargins(12, 16, 12, 16)
        nav_layout.setSpacing(4)

        self._buttons: list[NavButton] = []
        for label, idx in NAV_ITEMS:
            btn = NavButton(label, idx)
            btn.clicked.connect(lambda checked, i=idx: self._select(i))
            nav_layout.addWidget(btn)
            self._buttons.append(btn)

        nav_layout.addStretch()
        layout.addWidget(nav_container, 1)

        sep2 = QFrame()
        sep2.setFixedHeight(1)
        sep2.setObjectName("separator")
        layout.addWidget(sep2)

        status_frame = QFrame()
        status_frame.setObjectName("sidebarStatus")
        status_frame.setFixedHeight(72)
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(20, 12, 20, 12)
        status_layout.setSpacing(4)

        status_row = QHBoxLayout()
        self._status_dot = StatusDot(color="#5d6280", size=10)
        status_row.addWidget(self._status_dot)
        self._status_label = QLabel("Core: متوقف")
        self._status_label.setObjectName("sidebarStatusText")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_row.addWidget(self._status_label)
        status_row.addStretch()
        status_layout.addLayout(status_row)

        self._protection_label = QLabel("حفاظت: غیرفعال")
        self._protection_label.setObjectName("sidebarStatusText")
        self._protection_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_layout.addWidget(self._protection_label)

        layout.addWidget(status_frame)

    def _select(self, index: int) -> None:
        for btn in self._buttons:
            btn.set_active(btn.index == index)
        self.page_changed.emit(index)

    def update_core_status(self, state: str, color: str) -> None:
        self._status_dot.set_color(color)
        self._status_label.setText(f"Core: {state}")

    def update_protection_status(self, enabled: bool) -> None:
        p = get_palette()
        text = "فعال" if enabled else "غیرفعال"
        color = p.ok if enabled else p.text_muted
        self._protection_label.setText(f"حفاظت: {text}")
        self._protection_label.setStyleSheet(f"color: {color};")


class MainWindow(QMainWindow):
    """Main window with sidebar navigation."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ITShield Antivirus")
        self.resize(1280, 800)

        settings = get_settings()
        settings.ensure_dirs()
        self._db = Database(settings.db_path)
        run_migrations(self._db)

        self._bus = EventBus()
        self._bridge = BackgroundBridge(self)
        self._bridge.wire()

        self._scanner = FileScanner(
            hash_engine=HashEngine(),
            signature_engine=SignatureEngine(),
            yara_engine=YaraEngine(),
            analyzer=FileAnalyzer(),
        )
        self._quarantine = QuarantineEngine(db=self._db)
        self._incidents = IncidentManager(db=self._db)
        self._update_mgr = UpdateManager(
            db=self._db,
            current_bank_path=settings.signature_bank_path,
            backup_dir=settings.data_dir / "bank_backups",
        )
        self._yara_downloader = YaraRuleDownloader(
            db=self._db, rules_dir=settings.rules_dir,
        )

        central = QWidget()
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self._sidebar = Sidebar()
        self._sidebar.page_changed.connect(self._on_page_changed)
        main_layout.addWidget(self._sidebar)

        content_frame = QFrame()
        content_frame.setObjectName("contentArea")
        content_layout = QVBoxLayout(content_frame)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(56)
        topbar_layout = QHBoxLayout(topbar)
        topbar_layout.setContentsMargins(24, 0, 24, 0)

        self._page_title = QLabel("داشبورد")
        self._page_title.setObjectName("pageTitle")
        self._page_title.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        topbar_layout.addWidget(self._page_title)
        topbar_layout.addStretch()

        self._version_label = QLabel("")
        self._version_label.setObjectName("versionLabel")
        topbar_layout.addWidget(self._version_label)

        content_layout.addWidget(topbar)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setObjectName("separator")
        content_layout.addWidget(sep)

        self._pages = QStackedWidget()
        self._pages.setObjectName("pages")

        self._dashboard = DashboardTab()
        self._scan_tab = ScanTab(self._scanner, self._bridge)
        self._realtime_tab = RealtimeTab(self._scanner, self._quarantine, self._bridge)
        self._quarantine_tab = QuarantineTab(self._quarantine)
        self._events_tab = EventsTab(self._bus)
        self._system_tab = SystemTab()
        self._incidents_tab = IncidentsTab(self._incidents)
        self._update_tab = UpdateTab(
            self._update_mgr,
            yara_downloader=self._yara_downloader,
            bridge=self._bridge,
        )
        self._stats_tab = StatsTab(self._db)
        self._settings_tab = SettingsTab()

        for page in [
            self._dashboard, self._scan_tab, self._realtime_tab,
            self._quarantine_tab, self._events_tab, self._system_tab,
            self._incidents_tab, self._update_tab, self._stats_tab,
            self._settings_tab,
        ]:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(page)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            self._pages.addWidget(scroll)

        content_layout.addWidget(self._pages, 1)
        main_layout.addWidget(content_frame, 1)

        central.setLayout(main_layout)
        self.setCentralWidget(central)

        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("آماده")

        self._build_tray_icon()

        self._build_menu_bar()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._periodic_refresh)
        self._refresh_timer.start(2000)

        QTimer.singleShot(300, self._initial_refresh)

        self._bridge.subscribe("rtp_threat", self._on_threat_for_tray)
        self._bridge.subscribe("scan_result", self._on_scan_result_for_dashboard)
        self._bridge.subscribe("scan_done", self._on_scan_activity)
        self._bridge.subscribe("scan_progress", self._on_scan_activity)
        self._bridge.subscribe("rtp_event", self._on_rtp_event_for_dashboard)

    def _on_page_changed(self, index: int) -> None:
        self._pages.setCurrentIndex(index)
        if index < len(NAV_ITEMS):
            self._page_title.setText(NAV_ITEMS[index][0])

    def _build_menu_bar(self) -> None:
        mb = self.menuBar()

        file_menu = mb.addMenu("فایل")
        act_scan = QAction("اسکن جدید...", self)
        act_scan.setShortcut(QKeySequence("Ctrl+S"))
        act_scan.triggered.connect(lambda: self._sidebar._select(1))
        file_menu.addAction(act_scan)
        file_menu.addAction(QAction("-", self))  # separator hack
        act_quit = QAction("خروج", self)
        act_quit.setShortcut(QKeySequence("Ctrl+Q"))
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        view_menu = mb.addMenu("نمایش")
        for label, idx in NAV_ITEMS:
            act = QAction(label, self)
            act.triggered.connect(lambda checked=False, i=idx: self._sidebar._select(i))
            view_menu.addAction(act)
        view_menu.addSeparator()
        theme_menu = view_menu.addMenu("پوسته")
        act_dark = QAction("تیره", self, checkable=True)
        act_dark.setChecked(True)
        act_dark.triggered.connect(lambda: set_theme("dark"))
        act_light = QAction("روشن", self)
        act_light.triggered.connect(lambda: set_theme("light"))
        theme_menu.addAction(act_dark)
        theme_menu.addAction(act_light)

        help_menu = mb.addMenu("راهنما")
        act_about = QAction("درباره ITShield", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    def _build_tray_icon(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self._tray = None
            return

        pix = QPixmap(32, 32)
        pix.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.moveTo(16, 3)
        path.lineTo(27, 7)
        path.lineTo(27, 17)
        path.quadTo(27, 24, 16, 29)
        path.quadTo(5, 24, 5, 17)
        path.lineTo(5, 7)
        path.closeSubpath()
        painter.setPen(QPen(QColor("#10b981"), 2))
        painter.setBrush(QBrush(QColor("#061410")))
        painter.drawPath(path)
        painter.setPen(QPen(QColor("#10b981"), 2.5))
        painter.drawLine(11, 16, 15, 20)
        painter.drawLine(15, 20, 22, 11)
        painter.end()

        self._tray = QSystemTrayIcon(QIcon(pix), self)
        self._tray.setToolTip("ITShield Antivirus")

        menu = QMenu(self)
        act_show = QAction("نمایش پنجره", self)
        def _show():
            self.showNormal()
            self.raise_()
            self.activateWindow()
        act_show.triggered.connect(_show)
        menu.addAction(act_show)
        act_hide = QAction("مینیمایز", self)
        act_hide.triggered.connect(self.hide)
        menu.addAction(act_hide)
        menu.addSeparator()
        act_quit = QAction("خروج", self)
        act_quit.triggered.connect(self.close)
        menu.addAction(act_quit)
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self.showNormal()

    def _on_threat_for_tray(self, event) -> None:
        d = event.data
        name = Path(d.get("file_path", "")).name or "فایل ناشناس"
        reason = d.get("reason", "تهدید شناسایی شد")
        self._dashboard.append_activity(f"[THREAT] {name}")
        self.statusBar().showMessage(f"تهدید: {name}", 5000)
        if self._tray is not None:
            self._tray.showMessage(
                "تهدید شناسایی شد!",
                f"فایل: {name}\nدلیل: {reason}",
                QSystemTrayIcon.MessageSeverity.Critical, 5000,
            )

    def _show_about(self) -> None:
        QMessageBox.about(
            self, "درباره ITShield",
            "<h3>ITShield Antivirus</h3>"
            "<p>Endpoint Protection Platform</p>"
            "<p>Linux & Windows | Python + Rust + C++</p>"
        )

    def _initial_refresh(self) -> None:
        self._dashboard.update_engine_counts(
            len(self._scanner.signature_engine),
            self._scanner.yara_engine.rule_count,
        )
        self._dashboard.update_protection_status(False)
        self._dashboard.update_core_status("STOPPED")
        p = get_palette()
        self._sidebar.update_core_status("متوقف", p.text_muted)
        self._sidebar.update_protection_status(False)
        self._refresh_stats()

    def _periodic_refresh(self) -> None:
        try:
            self._refresh_stats()
        except Exception:
            pass

    def _refresh_stats(self) -> None:
        try:
            scanned = self._db.fetchone("SELECT COUNT(*) AS c FROM scan_results")
            threats = self._db.fetchone(
                "SELECT COUNT(*) AS c FROM scan_results WHERE detection IN ('MALICIOUS','SUSPICIOUS')"
            )
            quar = self._db.fetchone("SELECT COUNT(*) AS c FROM quarantine")
            inc = self._db.fetchone("SELECT COUNT(*) AS c FROM incidents WHERE state='OPEN'")
            self._dashboard.update_stats(
                scanned["c"] if scanned else 0,
                threats["c"] if threats else 0,
                quar["c"] if quar else 0,
                inc["c"] if inc else 0,
            )
        except Exception:
            pass

    def _on_scan_activity(self, event) -> None:
        d = event.data
        if event.kind == "scan_done":
            err = d.get("error")
            if err:
                self._dashboard.append_activity(f"[scan] خطا: {err}")
            else:
                self._dashboard.append_activity(
                    f"[scan] تکمیل: {d.get('files_scanned', 0)}/{d.get('files_total', 0)}"
                )
            self._refresh_stats()

    def _on_scan_result_for_dashboard(self, event) -> None:
        d = event.data
        verdict = d.get("verdict", "")
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            name = Path(d.get("file_path", "")).name
            self._dashboard.append_activity(f"[{verdict}] {name}")

    def _on_rtp_event_for_dashboard(self, event) -> None:
        d = event.data
        kind = d.get("kind", "")
        path = d.get("file_path", "")
        name = Path(path).name if path else ""
        if kind in ("FILE_CREATED", "FILE_MODIFIED"):
            self._dashboard.append_activity(f"[{kind}] {name}")

    def closeEvent(self, event) -> None:
        try:
            self._realtime_tab._stop()
        except Exception:
            pass
        try:
            self._db.close()
        except Exception:
            pass
        if hasattr(self, '_tray') and self._tray is not None:
            try:
                self._tray.hide()
            except Exception:
                pass
        super().closeEvent(event)


def _load_persian_font() -> str:
    """Load Vazirmatn font from assets/fonts/ directory.

    Returns the font family name if loaded, empty string if not.
    """
    from PySide6.QtGui import QFontDatabase
    font_dir = Path(__file__).resolve().parents[2] / "assets" / "fonts"
    family = ""
    for font_file in ["Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf"]:
        path = font_dir / font_file
        if path.exists():
            font_id = QFontDatabase.addApplicationFont(str(path))
            if font_id >= 0:
                families = QFontDatabase.applicationFontFamilies(font_id)
                if families:
                    family = families[0]
                    logger.info("Loaded font: %s from %s", family, path)
    return family


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("ITShield Antivirus")

    font_family = _load_persian_font()
    if font_family:
        font = QFont(font_family, 10)
        font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
        app.setFont(font)
    else:
        logger.warning("Vazirmatn font not found; using system default")

    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

    set_theme("dark")
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
