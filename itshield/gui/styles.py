"""ITShield GUI themes."""

from __future__ import annotations
from dataclasses import dataclass
from PySide6.QtWidgets import QApplication


@dataclass
class Palette:
    name: str
    bg: str; bg_alt: str; bg_input: str; bg_card: str; bg_card_hover: str
    border: str; border_strong: str; border_focus: str
    text: str; text_dim: str; text_muted: str
    accent: str; accent_hover: str; accent_pressed: str; accent_dim: str
    clean: str; suspicious: str; malicious: str; unknown: str; skipped: str
    sev_low: str; sev_medium: str; sev_high: str; sev_critical: str
    ok: str; warn: str; err: str; info: str


DARK = Palette(
    name="dark",
    bg="#0a0b14", bg_alt="#111320", bg_input="#070810",
    bg_card="#161827", bg_card_hover="#1c1f33",
    border="#3a3a4e", border_strong="#4a4a64", border_focus="#10b981",
    text="#e2e4ee", text_dim="#8b90a8", text_muted="#4a4f68",
    accent="#10b981", accent_hover="#34d399", accent_pressed="#059669",
    accent_dim="#0d2a1c",
    clean="#10b981", suspicious="#f59e0b", malicious="#ef4444",
    unknown="#6b7280", skipped="#a78bfa",
    sev_low="#10b981", sev_medium="#f59e0b", sev_high="#f97316", sev_critical="#ef4444",
    ok="#10b981", warn="#f59e0b", err="#ef4444", info="#3b82f6",
)

LIGHT = Palette(
    name="light",
    bg="#f8fafc", bg_alt="#ffffff", bg_input="#ffffff",
    bg_card="#ffffff", bg_card_hover="#f1f5f9",
    border="#cccccc", border_strong="#999999", border_focus="#10b981",
    text="#1e293b", text_dim="#64748b", text_muted="#94a3b8",
    accent="#059669", accent_hover="#10b981", accent_pressed="#047857",
    accent_dim="#d1fae5",
    clean="#059669", suspicious="#d97706", malicious="#dc2626",
    unknown="#6b7280", skipped="#7c3aed",
    sev_low="#059669", sev_medium="#d97706", sev_high="#ea580c", sev_critical="#dc2626",
    ok="#059669", warn="#d97706", err="#dc2626", info="#2563eb",
)

_PALETTES = {"dark": DARK, "light": LIGHT}
_current: Palette = DARK

def get_palette() -> Palette:
    return _current

def set_theme(name: str) -> None:
    global _current
    if name not in _PALETTES:
        raise ValueError(f"Unknown theme: {name!r}")
    _current = _PALETTES[name]
    app = QApplication.instance()
    if app is not None:
        from PySide6.QtCore import Qt
        app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        app.setStyleSheet(stylesheet())

def stylesheet() -> str:
    p = _current
    f = '"Vazirmatn", "DejaVu Sans", "Sans"'
    return f"""
        * {{
            font-family: {f};
            font-size: 13px;
        }}
        QWidget {{
            background-color: {p.bg};
            color: {p.text};
        }}
        QMainWindow {{
            background-color: {p.bg};
        }}

        QMenuBar {{
            background-color: {p.bg_alt};
            color: {p.text_dim};
            border-bottom: 1px solid {p.border};
            padding: 2px 8px;
            font-weight: 500;
        }}
        QMenuBar::item {{
            background: transparent;
            padding: 6px 14px;
            border-radius: 4px;
        }}
        QMenuBar::item:selected {{
            background-color: {p.accent_dim};
            color: {p.accent};
        }}
        QMenu {{
            background-color: {p.bg_alt};
            color: {p.text};
            border: 1px solid {p.border};
            border-radius: 8px;
            padding: 6px;
        }}
        QMenu::item {{
            padding: 8px 24px 8px 16px;
            border-radius: 4px;
        }}
        QMenu::item:selected {{
            background-color: {p.accent_dim};
            color: {p.accent};
        }}
        QMenu::separator {{
            height: 1px;
            background: {p.border};
            margin: 4px 8px;
        }}

        QTabWidget::pane {{
            border: 1px solid {p.border};
            border-top: none;
            border-radius: 0 0 8px 8px;
            background-color: {p.bg};
        }}
        QTabBar::tab {{
            background-color: {p.bg_alt};
            color: {p.text_dim};
            padding: 10px 22px;
            border: 1px solid {p.border};
            border-bottom: none;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            margin-left: 3px;
            min-width: 95px;
            font-weight: 500;
        }}
        QTabBar::tab:selected {{
            background-color: {p.bg};
            color: {p.text};
            border-bottom: 3px solid {p.accent};
            font-weight: 600;
            padding-bottom: 7px;
        }}
        QTabBar::tab:hover:!selected {{
            background-color: {p.bg_card};
            color: {p.text};
        }}
        QTabBar::tab:!selected {{
            margin-top: 3px;
        }}

        QPushButton {{
            background-color: {p.bg_card};
            color: {p.text};
            border: 1px solid {p.border};
            padding: 8px 18px;
            border-radius: 6px;
            font-weight: 500;
        }}
        QPushButton:hover {{
            background-color: {p.bg_card_hover};
            border-color: {p.border_strong};
        }}
        QPushButton:pressed {{
            background-color: {p.bg_input};
        }}
        QPushButton:disabled {{
            color: {p.text_muted};
        }}
        QPushButton#primary {{
            background-color: {p.accent};
            color: #ffffff;
            border: none;
            font-weight: 600;
        }}
        QPushButton#primary:hover {{
            background-color: {p.accent_hover};
        }}
        QPushButton#danger {{
            background-color: {p.err};
            color: #ffffff;
            border: none;
            font-weight: 600;
        }}

        QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit {{
            background-color: {p.bg_input};
            color: {p.text};
            border: 1px solid {p.border};
            padding: 8px 10px;
            border-radius: 5px;
            selection-background-color: {p.accent};
            selection-color: #ffffff;
        }}
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus,
        QPlainTextEdit:focus, QTextEdit:focus {{
            border: 2px solid {p.border_focus};
            padding: 7px 9px;
        }}

        QTableWidget {{
            background-color: {p.bg_alt};
            color: {p.text};
            gridline-color: {p.border};
            border: 1px solid {p.border};
            border-radius: 8px;
            selection-background-color: {p.accent};
            selection-color: #ffffff;
            alternate-background-color: {p.bg_card};
        }}
        QTableWidget::item {{
            padding: 6px 10px;
        }}
        QHeaderView::section {{
            background-color: {p.bg_input};
            color: {p.text_dim};
            padding: 10px 12px;
            border: none;
            border-right: 1px solid {p.border};
            border-bottom: 1px solid {p.border};
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
        }}

        QProgressBar {{
            background-color: {p.bg_input};
            border: 1px solid {p.border};
            border-radius: 5px;
            text-align: center;
            color: {p.text};
            min-height: 22px;
            max-height: 24px;
        }}
        QProgressBar::chunk {{
            background-color: {p.accent};
            border-radius: 4px;
            margin: 1px;
        }}

        QLabel#title {{
            font-size: 22px;
            font-weight: 700;
            color: {p.text};
        }}
        QLabel#subtitle {{
            color: {p.text_dim};
            font-size: 13px;
        }}
        QLabel#stat_value {{
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -1px;
        }}
        QLabel#stat_label {{
            color: {p.text_muted};
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        QLabel#hero_title {{
            font-size: 28px;
            font-weight: 800;
            color: {p.text};
        }}
        QLabel#hero_subtitle {{
            font-size: 14px;
            color: {p.text_dim};
        }}

        QStatusBar {{
            background-color: {p.bg_alt};
            color: {p.text_dim};
            border-top: 1px solid {p.border};
            padding: 4px 14px;
            font-size: 12px;
        }}
        QStatusBar::item {{
            border: none;
        }}

        QGroupBox {{
            border: 1px solid {p.border};
            border-radius: 8px;
            margin-top: 16px;
            padding-top: 12px;
            color: {p.text_dim};
            font-weight: 600;
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            right: 12px;
            padding: 0 8px;
        }}

        QCheckBox {{
            color: {p.text};
            spacing: 8px;
        }}
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border: 2px solid {p.border_strong};
            background-color: {p.bg_input};
            border-radius: 4px;
        }}
        QCheckBox::indicator:hover {{
            border-color: {p.accent};
        }}
        QCheckBox::indicator:checked {{
            background-color: {p.accent};
            border-color: {p.accent};
        }}

        QScrollBar:vertical {{
            background: {p.bg_alt};
            width: 8px;
            border: none;
        }}
        QScrollBar::handle:vertical {{
            background: {p.border_strong};
            min-height: 40px;
            border-radius: 4px;
            margin: 1px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {p.text_muted};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        QScrollBar:horizontal {{
            background: {p.bg_alt};
            height: 8px;
            border: none;
        }}
        QScrollBar::handle:horizontal {{
            background: {p.border_strong};
            min-width: 40px;
            border-radius: 4px;
            margin: 1px;
        }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}

        QScrollArea {{
            border: none;
            background: transparent;
        }}

        QToolTip {{
            background-color: {p.bg_card};
            color: {p.text};
            border: 1px solid {p.border_strong};
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 12px;
        }}

        QFrame#StatCard {{
            background-color: {p.bg_card};
            border: 1px solid {p.border};
            border-radius: 10px;
        }}
        QFrame#StatCard:hover {{
            border-color: {p.border_strong};
            background-color: {p.bg_card_hover};
        }}
        QFrame#Hero {{
            background-color: {p.bg_card};
            border: 1px solid {p.border};
            border-radius: 10px;
        }}
        QFrame#Header {{
            background-color: {p.bg_alt};
            border-bottom: 1px solid {p.border};
        }}

        QPushButton#navButton {{
            background-color: {p.bg_card};
            color: {p.text_dim};
            border: 1px solid {p.border};
            border-radius: 6px;
            padding: 10px 14px;
            text-align: right;
            font-weight: 500;
            font-size: 13px;
            margin-bottom: 4px;
        }}
        QPushButton#navButton:hover {{
            background-color: {p.bg_card_hover};
            border-color: {p.border_strong};
            color: {p.text};
        }}
        QPushButton#navButton:checked {{
            background-color: {p.accent_dim};
            color: {p.accent};
            border: 1px solid {p.accent};
            font-weight: 600;
        }}

        QLabel#sidebarTitle {{
            font-size: 18px;
            font-weight: 800;
            color: {p.accent};
            letter-spacing: 1px;
        }}
        QLabel#sidebarStatusText {{
            font-size: 11px;
            color: {p.text_dim};
        }}
        QFrame#sidebar {{
            background-color: {p.bg_alt};
            border-left: 1px solid {p.border};
        }}
        QFrame#sidebarLogo {{
            background-color: {p.bg_alt};
        }}
        QFrame#sidebarStatus {{
            background-color: {p.bg_alt};
        }}
        QFrame#separator {{
            background-color: {p.border};
        }}

        QFrame#topbar {{
            background-color: {p.bg_alt};
        }}
        QLabel#pageTitle {{
            font-size: 16px;
            font-weight: 700;
            color: {p.text};
        }}
        QLabel#versionLabel {{
            font-size: 11px;
            color: {p.text_muted};
            background-color: {p.bg_card};
            padding: 4px 10px;
            border-radius: 10px;
        }}

        QFrame#contentArea {{
            background-color: {p.bg};
            border-left: 1px solid {p.border};
        }}

        QStackedWidget {{
            background-color: {p.bg};
        }}

        QTextEdit#eventLog {{
            background-color: {p.bg_input};
            color: {p.text};
            border: 1px solid {p.border};
            border-radius: 6px;
            font-family: "Vazirmatn", "DejaVu Sans Mono", monospace;
            font-size: 12px;
        }}
        QLabel#emptyState {{
            color: {p.text_muted};
            font-size: 14px;
            padding: 40px;
        }}
    """
