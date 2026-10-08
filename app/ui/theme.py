"""Futuristic desktop palette with native controls and visible focus states."""

from pathlib import Path

STYLE = """
QWidget { background: #070b14; color: #e7f1ff; font-family: 'DejaVu Sans'; font-size: 13px; }
QLabel { background: transparent; }
QWidget#sidebar { background: #080d19; border-right: 1px solid #1a3150; }
QWidget#sidebar QLabel { color: #7f9bb8; background: transparent; }
QWidget#sidebar QLabel#brand { color: #f4fbff; font-size: 23px; font-weight: bold; }
QWidget#sidebar QLabel#eyebrow { color: #00d9ff; }
QWidget#topbar { background: #0b1221; border-bottom: 1px solid #1b3858; }
QLabel#brand { font-size: 19px; font-weight: bold; color: #f4fbff; }
QLabel#eyebrow { color: #6e91b1; font-size: 11px; font-weight: bold; }
QLabel#system-checking { color: #f0c96a; font-size: 11px; font-weight: bold; }
QLabel#system-online { color: #39f29f; font-size: 11px; font-weight: bold; }
QLabel#system-offline { color: #ff5577; font-size: 11px; font-weight: bold; }
QLabel#title { font-size: 29px; font-weight: bold; color: #f4fbff; }
QLabel#muted { color: #9ab3cc; }
QLabel#notice { background: #0b2030; color: #8ceaff; padding: 13px; border: 1px solid #145273; border-radius: 8px; }
QLabel#error { background: #301522; color: #ff9fb5; padding: 13px; border: 1px solid #8e3457; border-radius: 8px; }
QWidget#card { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #101c2e, stop:1 #0b1423); border: 1px solid #1d4263; border-radius: 13px; }
QWidget#card QLabel { background: transparent; border: none; }
QWidget#subcard { background: rgba(7, 16, 30, 180); border: 1px solid #1a3a59; border-radius: 10px; }
QWidget#subcard:hover { border: 1px solid #236687; }
QLabel#section-label { color: #4fe5ff; font-size: 11px; font-weight: bold; }
QLabel#section-copy { color: #7f9fbb; font-size: 12px; }
QLabel#field-label { color: #88a8c2; font-size: 12px; padding-left: 4px; }
QWidget#action-strip { background: transparent; border-top: 1px solid #1a3a59; }
QLabel#metric { font-family: 'DejaVu Sans Mono'; font-size: 31px; font-weight: bold; color: #00e5ff; }
QListWidget { background: transparent; border: none; outline: none; }
QListWidget::item { padding: 13px 12px; margin: 3px 0; border-radius: 7px; color: #94abc2; }
QListWidget::item:selected { background: #102e45; color: #e8fbff; border-left: 3px solid #00e5ff; }
QListWidget::item:hover { background: #0d2237; color: #d6f7ff; }
QListWidget:focus { border: 1px solid #00b9dc; }
QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #007fba, stop:1 #00c8d9); color: #00141d; border: 1px solid #27e7f5; border-radius: 7px; padding: 10px 16px; font-weight: bold; min-height: 18px; }
QPushButton:hover { background: #00e5ff; color: #001017; }
QPushButton:focus { border: 2px solid #e8fbff; }
QPushButton:disabled { background: #122235; color: #59718b; border: 1px solid #213b57; }
QPushButton#secondary { background: #0d1828; color: #b6d2e9; border: 1px solid #2c4d6a; }
QPushButton#secondary:hover { background: #12314b; color: #e7faff; border: 1px solid #00b9dc; }
QPushButton#secondary:disabled { background: #0e1725; color: #536a82; border: 1px solid #1c324a; }
QPushButton#secondary:focus { border: 2px solid #00d9ff; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background: #0a1423; color: #e7f1ff; border: 1px solid #294764; border-radius: 7px; padding: 9px; selection-background-color: #125477; selection-color: #ffffff; }
QComboBox:disabled, QSpinBox:disabled { background: #0c1522; color: #59718b; }
QComboBox QAbstractItemView { background: #0b1626; color: #e7f1ff; selection-background-color: #123e5a; selection-color: #ffffff; }
QComboBox::drop-down { width: 24px; border: none; }
QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus { border: 2px solid #00cbe8; }
QCheckBox { spacing: 8px; background: transparent; color: #b5cbe0; }
QCheckBox:focus { border: 1px solid #00cbe8; }
QCheckBox::indicator { width: 18px; height: 18px; }
QCheckBox::indicator:unchecked { background: #0b1727; border: 1px solid #42627e; border-radius: 4px; }
QCheckBox::indicator:checked { background: #00bdd6; border: 1px solid #6ff4ff; border-radius: 4px; }
QTableWidget { background: #091320; alternate-background-color: #0c1928; color: #d9e9f7; border: 1px solid #1e3c5a; border-radius: 8px; gridline-color: #142b42; selection-background-color: #114a69; selection-color: #ffffff; }
QTableWidget:focus { border: 1px solid #00cbe8; }
QHeaderView::section { background: #0e1e31; color: #7fa8c8; padding: 12px 8px; border: none; border-bottom: 1px solid #1d4263; font-size: 12px; font-weight: bold; }
QTableCornerButton::section { background: #0e1e31; border: none; }
QProgressBar { background: #122236; border: none; border-radius: 4px; height: 7px; text-align: center; }
QProgressBar::chunk { background: #00d9ff; border-radius: 4px; }
QScrollArea#page-scroll { background: #070b14; border: none; }
QScrollBar:vertical { background: #091321; width: 12px; margin: 3px; border-radius: 6px; }
QScrollBar::handle:vertical { background: #1f5574; min-height: 56px; border-radius: 6px; }
QScrollBar::handle:vertical:hover { background: #00b9dc; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollArea { border: none; }
QSplitter::handle { background: #16324d; }
QStatusBar { background: #080f1c; color: #7fa8c8; border-top: 1px solid #16334e; }
QToolTip { background: #091827; color: #e7faff; border: 1px solid #00a8c9; padding: 7px; }
"""

STYLE += (
    'QComboBox::down-arrow { image: url("'
    + (Path(__file__).parents[1] / "resources/icons/chevron-down.svg").as_posix()
    + '"); width: 12px; height: 12px; }'
)
