from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QScrollArea, QFrame
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

BG_DARK   = "#0a0e17"
BG_PANEL  = "#0f1623"
BORDER    = "#1e2d47"
ACCENT    = "#00d4ff"
TEXT      = "#e8edf5"
MUTED     = "#5a6a82"
FONT_MONO = "Courier New"
FONT_UI   = "Segoe UI"

class AIReportWindow(QWidget):
    def __init__(self, report_text):
        super().__init__()
        self.setWindowTitle("AI Analyst Report")
        self.setMinimumSize(800, 600)
        self.setStyleSheet(f"background: {BG_DARK};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QFrame()
        header.setFixedHeight(56)
        header.setStyleSheet(f"background: {BG_PANEL}; border-bottom: 1px solid {BORDER};")
        hl = QVBoxLayout(header)
        hl.setContentsMargins(24, 0, 24, 0)
        title = QLabel("◈  AI Analyst Report")
        title.setFont(QFont(FONT_UI, 14, QFont.Bold))
        title.setStyleSheet(f"color: {ACCENT}; border: none; background: transparent;")
        title.setAlignment(Qt.AlignVCenter)
        hl.addWidget(title)
        layout.addWidget(header)

        # Scrollable report text
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: {BG_DARK}; }}
            QScrollBar:vertical {{
                background: {BG_PANEL}; width: 8px; border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER}; border-radius: 4px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{ height: 0px; }}
        """)

        content = QLabel(report_text)
        content.setFont(QFont(FONT_MONO, 10))
        content.setStyleSheet(f"""
            color: {TEXT};
            background: {BG_DARK};
            padding: 28px;
            border: none;
        """)
        content.setWordWrap(True)
        content.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        content.setTextInteractionFlags(Qt.TextSelectableByMouse)

        scroll.setWidget(content)
        layout.addWidget(scroll)
