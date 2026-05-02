import sys
import json
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QLineEdit, QScrollArea,
    QFrame, QSizePolicy, QGraphicsDropShadowEffect, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPalette

# ── Make sure Python can find the core modules ──────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from core.parser import parse_pcap
from core.flow_builder import build_flows
from core.detector import detect_all


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  COLORS & FONTS                                                      ║
# ╚══════════════════════════════════════════════════════════════════════╝
BG_DARK       = "#0a0e17"
BG_PANEL      = "#0f1623"
BG_CARD       = "#141d2e"
BORDER        = "#1e2d47"
ACCENT_BLUE   = "#0d7fe8"
ACCENT_CYAN   = "#00d4ff"
RED_ALERT     = "#ff3b5c"
AMBER_WARN    = "#ffb020"
GREEN_OK      = "#00e676"
TEXT_PRIMARY  = "#e8edf5"
TEXT_MUTED    = "#5a6a82"
TEXT_DIM      = "#3a4a62"
FONT_MONO     = "Courier New"
FONT_UI       = "Segoe UI"


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  ANALYSIS THREAD                                                     ║
# ╚══════════════════════════════════════════════════════════════════════╝
class AnalysisThread(QThread):
    done   = pyqtSignal(list)
    error  = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, filepath):
        super().__init__()
        self.filepath        = filepath
        self.packets         = []
        self.flow_table      = {}
        self.source_activity = {}
        self.arp_map         = {}

    def run(self):
        try:
            self.status.emit("Parsing packets...")
            self.packets = parse_pcap(self.filepath)
            self.status.emit(f"Parsed {len(self.packets)} packets — building flows...")
            self.flow_table, self.source_activity, self.arp_map = build_flows(self.packets)
            self.status.emit("Running detectors...")
            alerts = detect_all(self.flow_table, self.source_activity, self.arp_map)
            self.done.emit(alerts)
        except Exception as e:
            self.error.emit(str(e))


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  AI THREAD  (keeps UI responsive during API call)                   ║
# ╚══════════════════════════════════════════════════════════════════════╝
class AIThread(QThread):
    done  = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, packets, flow_table, source_activity):
        super().__init__()
        self.packets         = packets
        self.flow_table      = flow_table
        self.source_activity = source_activity

    def run(self):
        try:
            from core.ai_analyst import ai_analyze_pcap
            report = ai_analyze_pcap(self.packets, self.flow_table, self.source_activity)
            self.done.emit(report)
        except Exception as e:
            self.error.emit(str(e))


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  STYLED ACTION BUTTON                                                ║
# ╚══════════════════════════════════════════════════════════════════════╝
class ActionButton(QPushButton):
    def __init__(self, label, color=ACCENT_BLUE, text_color="#ffffff", parent=None):
        super().__init__(label, parent)
        self.setFixedHeight(34)
        self.setCursor(Qt.PointingHandCursor)
        self.setFont(QFont(FONT_UI, 9, QFont.Bold))
        self.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {color};
                border: 1.5px solid {color};
                border-radius: 6px;
                padding: 0 16px;
            }}
            QPushButton:hover {{
                background: {color};
                color: {text_color};
            }}
            QPushButton:pressed {{ background: {color}cc; }}
        """)


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  ALERT CARD                                                          ║
# ╚══════════════════════════════════════════════════════════════════════╝
class AlertCard(QFrame):
    ACTION_COLORS = {
        "Block IP":             RED_ALERT,
        "Block Source IP":      RED_ALERT,
        "Block Destination IP": RED_ALERT,
        "Block Domain":         AMBER_WARN,
        "Block Both":           RED_ALERT,
        "Ban IP":               RED_ALERT,
        "Ban Domain":           AMBER_WARN,
        "Isolate Host":         AMBER_WARN,
        "Rate Limit":           ACCENT_BLUE,
        "Alert Only":           ACCENT_CYAN,
        "Throttle & Monitor":   ACCENT_CYAN,
        "Investigate":          GREEN_OK,
        "Log & Investigate":    GREEN_OK,
        "Alert & Monitor":      ACCENT_CYAN,
        "Whitelist":            GREEN_OK,
    }

    def __init__(self, alert, parent=None):
        super().__init__(parent)
        self.alert = alert
        self._build()

    def _tier_color(self):
        return RED_ALERT if self.alert.get("tier") == "AUTO" else AMBER_WARN

    def _build(self):
        tier  = self.alert.get("tier", "AUTO")
        color = self._tier_color()

        self.setStyleSheet(f"""
            QFrame {{
                background: {BG_CARD};
                border: 1px solid {BORDER};
                border-left: 4px solid {color};
                border-radius: 8px;
            }}
        """)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(0, 0, 0, 120))
        self.setGraphicsEffect(shadow)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(10)

        # ── Header ──────────────────────────────────────────────────────
        header = QHBoxLayout()

        badge = QLabel(f" {tier} ")
        badge.setFont(QFont(FONT_MONO, 8, QFont.Bold))
        badge.setStyleSheet(f"""
            color: {color}; background: {color}22;
            border: 1px solid {color}55; border-radius: 4px; padding: 2px 6px;
        """)

        attack_name = QLabel(self.alert.get("attack", "Unknown Attack"))
        attack_name.setFont(QFont(FONT_UI, 13, QFont.Bold))
        attack_name.setStyleSheet(f"color: {TEXT_PRIMARY}; border: none; background: transparent;")

        mitre = QLabel(self.alert.get("mitre", ""))
        mitre.setFont(QFont(FONT_MONO, 9))
        mitre.setStyleSheet(f"""
            color: {ACCENT_CYAN}; background: {ACCENT_CYAN}15;
            border: 1px solid {ACCENT_CYAN}40; border-radius: 4px; padding: 2px 8px;
        """)

        header.addWidget(badge)
        header.addSpacing(10)
        header.addWidget(attack_name)
        header.addStretch()
        header.addWidget(mitre)
        root.addLayout(header)

        # ── Divider ──────────────────────────────────────────────────────
        div = QFrame()
        div.setFrameShape(QFrame.HLine)
        div.setStyleSheet(f"border: none; background: {BORDER}; max-height: 1px;")
        root.addWidget(div)

        # ── Info grid ────────────────────────────────────────────────────
        info = QHBoxLayout()
        info.setSpacing(24)

        def info_block(label, value, val_color=TEXT_PRIMARY):
            col = QVBoxLayout()
            col.setSpacing(2)
            lbl = QLabel(label.upper())
            lbl.setFont(QFont(FONT_MONO, 7))
            lbl.setStyleSheet(f"color: {TEXT_MUTED}; border: none; background: transparent;")
            val = QLabel(value)
            val.setFont(QFont(FONT_MONO, 10))
            val.setStyleSheet(f"color: {val_color}; border: none; background: transparent;")
            val.setWordWrap(True)
            col.addWidget(lbl)
            col.addWidget(val)
            return col

        info.addLayout(info_block("Source IP", self.alert.get("src_ip", "N/A"), RED_ALERT))
        if self.alert.get("dst_ip"):
            info.addLayout(info_block("Dest IP", self.alert.get("dst_ip"), AMBER_WARN))
        info.addLayout(info_block("Evidence", self.alert.get("evidence", "—"), TEXT_PRIMARY))
        if self.alert.get("note"):
            info.addLayout(info_block("Note", self.alert.get("note"), ACCENT_CYAN))
        info.addStretch()
        root.addLayout(info)

        # ── Actions ──────────────────────────────────────────────────────
        action_row = QHBoxLayout()
        action_row.setSpacing(10)

        if tier == "AUTO":
            action_map = {
                "block_ip":            ["Block IP"],
                "block_ip_rate_limit": ["Block IP", "Rate Limit"],
                "drop_arp":            ["Block IP", "Alert Only"],
            }
            lbl_tag = QLabel("AUTO ACTION:")
            lbl_tag.setFont(QFont(FONT_MONO, 8))
            lbl_tag.setStyleSheet(f"color: {TEXT_MUTED}; border: none; background: transparent;")
            action_row.addWidget(lbl_tag)
            for label in action_map.get(self.alert.get("action", "block_ip"), ["Block IP"]):
                btn = ActionButton(label, self.ACTION_COLORS.get(label, RED_ALERT))
                btn.clicked.connect(lambda _, l=label, a=self.alert: self._execute(l, a))
                action_row.addWidget(btn)
        else:
            lbl_tag = QLabel("ANALYST DECISION:")
            lbl_tag.setFont(QFont(FONT_MONO, 8))
            lbl_tag.setStyleSheet(f"color: {AMBER_WARN}; border: none; background: transparent;")
            action_row.addWidget(lbl_tag)
            for opt in self.alert.get("options", ["Investigate"]):
                btn = ActionButton(opt, self.ACTION_COLORS.get(opt, ACCENT_BLUE))
                btn.clicked.connect(lambda _, l=opt, a=self.alert: self._execute(l, a))
                action_row.addWidget(btn)

        action_row.addStretch()
        root.addLayout(action_row)

    def _execute(self, action, alert):
        src  = alert.get("src_ip", "N/A")
        dst  = alert.get("dst_ip", "")
        name = alert.get("attack", "Unknown")
        msg  = QMessageBox()
        msg.setWindowTitle("Action Executed")
        msg.setText(f"<b>{action}</b> triggered for <b>{name}</b>")
        detail = f"Source IP : {src}"
        if dst:
            detail += f"\nDest IP   : {dst}"
        detail += f"\nAction    : {action}"
        detail += f"\n\n[Simulation mode — wire to iptables/firewall API for live blocking]"
        msg.setInformativeText(detail)
        msg.setStyleSheet(f"""
            QMessageBox {{ background: {BG_PANEL}; color: {TEXT_PRIMARY}; }}
            QPushButton {{ background: {ACCENT_BLUE}; color: white;
                           border-radius: 4px; padding: 6px 20px; border: none; }}
        """)
        msg.exec_()


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  AI REPORT WINDOW                                                    ║
# ╚══════════════════════════════════════════════════════════════════════╝
class AIReportWindow(QWidget):
    def __init__(self, report_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NetSentinel — AI Analyst Report")
        self.setMinimumSize(860, 640)
        self.setStyleSheet(f"background: {BG_DARK};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setFixedHeight(56)
        header.setStyleSheet(f"background: {BG_PANEL}; border-bottom: 1px solid {BORDER};")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(24, 0, 24, 0)

        icon = QLabel("◈")
        icon.setFont(QFont(FONT_UI, 16))
        icon.setStyleSheet(f"color: {ACCENT_CYAN}; background: transparent; border: none;")

        title = QLabel("AI Analyst Report")
        title.setFont(QFont(FONT_UI, 14, QFont.Bold))
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent; border: none;")

        badge = QLabel(" CLAUDE ANALYSIS ")
        badge.setFont(QFont(FONT_MONO, 8, QFont.Bold))
        badge.setStyleSheet(f"""
            color: {ACCENT_CYAN}; background: {ACCENT_CYAN}15;
            border: 1px solid {ACCENT_CYAN}40; border-radius: 4px; padding: 2px 8px;
        """)

        hl.addWidget(icon)
        hl.addSpacing(10)
        hl.addWidget(title)
        hl.addStretch()
        hl.addWidget(badge)
        layout.addWidget(header)

        # Scrollable report content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: {BG_DARK}; }}
            QScrollBar:vertical {{
                background: {BG_PANEL}; width: 8px; border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER}; border-radius: 4px; min-height: 30px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {ACCENT_CYAN}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        """)

        content = QLabel(report_text)
        content.setFont(QFont(FONT_MONO, 10))
        content.setStyleSheet(f"""
            color: {TEXT_PRIMARY}; background: {BG_DARK};
            padding: 28px; border: none;
        """)
        content.setWordWrap(True)
        content.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        content.setTextInteractionFlags(Qt.TextSelectableByMouse)

        scroll.setWidget(content)
        layout.addWidget(scroll)


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  MAIN WINDOW                                                         ║
# ╚══════════════════════════════════════════════════════════════════════╝
class ThreatDetectorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSentinel — Threat Detection Platform")
        self.setMinimumSize(1100, 750)

        # Storage for last parsed PCAP data (needed by AI analysis)
        self._last_packets         = []
        self._last_flow_table      = {}
        self._last_source_activity = {}
        self._pcap_loaded          = False

        self._apply_palette()
        self._build_ui()

    def _apply_palette(self):
        pal = QPalette()
        pal.setColor(QPalette.Window,     QColor(BG_DARK))
        pal.setColor(QPalette.WindowText, QColor(TEXT_PRIMARY))
        pal.setColor(QPalette.Base,       QColor(BG_PANEL))
        pal.setColor(QPalette.Text,       QColor(TEXT_PRIMARY))
        self.setPalette(pal)
        self.setStyleSheet(f"QMainWindow {{ background: {BG_DARK}; }}")

    # ── UI CONSTRUCTION ─────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main = QVBoxLayout(central)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        main.addWidget(self._build_header())
        main.addWidget(self._build_toolbar())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: {BG_DARK}; }}
            QScrollBar:vertical {{
                background: {BG_PANEL}; width: 8px; border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER}; border-radius: 4px; min-height: 30px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {ACCENT_BLUE}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        """)

        self.alert_container = QWidget()
        self.alert_container.setStyleSheet(f"background: {BG_DARK};")
        self.alert_layout = QVBoxLayout(self.alert_container)
        self.alert_layout.setContentsMargins(24, 24, 24, 24)
        self.alert_layout.setSpacing(14)
        self.alert_layout.addStretch()

        scroll.setWidget(self.alert_container)
        main.addWidget(scroll)
        main.addWidget(self._build_statusbar())

    def _build_header(self):
        header = QFrame()
        header.setFixedHeight(70)
        header.setStyleSheet(f"background: {BG_PANEL}; border-bottom: 1px solid {BORDER};")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(28, 0, 28, 0)

        logo = QLabel("◈")
        logo.setFont(QFont(FONT_UI, 20))
        logo.setStyleSheet(f"color: {ACCENT_CYAN}; background: transparent; border: none;")

        title = QLabel("NetSentinel")
        title.setFont(QFont(FONT_UI, 18, QFont.Bold))
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent; border: none;")

        subtitle = QLabel("Network Threat Detection Platform")
        subtitle.setFont(QFont(FONT_UI, 9))
        subtitle.setStyleSheet(f"color: {TEXT_MUTED}; background: transparent; border: none;")

        self.stats_label = QLabel("No file loaded")
        self.stats_label.setFont(QFont(FONT_MONO, 9))
        self.stats_label.setStyleSheet(f"color: {TEXT_MUTED}; background: transparent; border: none;")
        self.stats_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        hl.addWidget(logo)
        hl.addSpacing(8)
        hl.addWidget(title)
        hl.addSpacing(12)
        hl.addWidget(subtitle)
        hl.addStretch()
        hl.addWidget(self.stats_label)
        return header

    def _build_toolbar(self):
        bar = QFrame()
        bar.setFixedHeight(60)
        bar.setStyleSheet(f"background: {BG_PANEL}; border-bottom: 1px solid {BORDER};")
        hl = QHBoxLayout(bar)
        hl.setContentsMargins(24, 0, 24, 0)
        hl.setSpacing(12)

        # Path input
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter PCAP file path or click Browse...")
        self.path_input.setFixedHeight(36)
        self.path_input.setFont(QFont(FONT_MONO, 9))
        self.path_input.setStyleSheet(f"""
            QLineEdit {{
                background: {BG_DARK}; color: {TEXT_PRIMARY};
                border: 1.5px solid {BORDER}; border-radius: 6px; padding: 0 12px;
            }}
            QLineEdit:focus {{ border-color: {ACCENT_BLUE}; }}
        """)

        # Browse
        btn_browse = QPushButton("Browse")
        btn_browse.setFixedSize(90, 36)
        btn_browse.setCursor(Qt.PointingHandCursor)
        btn_browse.setFont(QFont(FONT_UI, 9))
        btn_browse.setStyleSheet(f"""
            QPushButton {{
                background: {BG_DARK}; color: {TEXT_MUTED};
                border: 1.5px solid {BORDER}; border-radius: 6px;
            }}
            QPushButton:hover {{ border-color: {ACCENT_BLUE}; color: {TEXT_PRIMARY}; }}
        """)
        btn_browse.clicked.connect(self._browse)

        # Analyze
        btn_analyze = QPushButton("▶  Analyze")
        btn_analyze.setFixedSize(120, 36)
        btn_analyze.setCursor(Qt.PointingHandCursor)
        btn_analyze.setFont(QFont(FONT_UI, 10, QFont.Bold))
        btn_analyze.setStyleSheet(f"""
            QPushButton {{
                background: {ACCENT_BLUE}; color: white;
                border: none; border-radius: 6px;
            }}
            QPushButton:hover {{ background: #1a8ff5; }}
            QPushButton:pressed {{ background: #0a6fcc; }}
            QPushButton:disabled {{ background: {BORDER}; color: {TEXT_DIM}; }}
        """)
        btn_analyze.clicked.connect(self._run_analysis)
        self.btn_analyze = btn_analyze

        # Clear
        btn_clear = QPushButton("Clear")
        btn_clear.setFixedSize(80, 36)
        btn_clear.setCursor(Qt.PointingHandCursor)
        btn_clear.setFont(QFont(FONT_UI, 9))
        btn_clear.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {TEXT_MUTED};
                border: 1.5px solid {BORDER}; border-radius: 6px;
            }}
            QPushButton:hover {{ color: {RED_ALERT}; border-color: {RED_ALERT}; }}
        """)
        btn_clear.clicked.connect(self._clear_alerts)

        # AI Analysis — disabled until a PCAP is analyzed
        btn_ai = QPushButton("◈  AI Analysis")
        btn_ai.setFixedSize(140, 36)
        btn_ai.setCursor(Qt.PointingHandCursor)
        btn_ai.setFont(QFont(FONT_UI, 10, QFont.Bold))
        btn_ai.setEnabled(False)
        btn_ai.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {ACCENT_CYAN};
                border: 1.5px solid {ACCENT_CYAN}; border-radius: 6px;
            }}
            QPushButton:hover {{ background: {ACCENT_CYAN}; color: #000000; }}
            QPushButton:pressed {{ background: {ACCENT_CYAN}cc; }}
            QPushButton:disabled {{ border-color: {BORDER}; color: {TEXT_DIM}; }}
        """)
        btn_ai.clicked.connect(self._run_ai_analysis)
        self.btn_ai = btn_ai

        hl.addWidget(self.path_input)
        hl.addWidget(btn_browse)
        hl.addWidget(btn_analyze)
        hl.addWidget(btn_clear)
        hl.addWidget(btn_ai)
        return bar

    def _build_statusbar(self):
        bar = QFrame()
        bar.setFixedHeight(30)
        bar.setStyleSheet(f"background: {BG_PANEL}; border-top: 1px solid {BORDER};")
        hl = QHBoxLayout(bar)
        hl.setContentsMargins(24, 0, 24, 0)

        self.status_label = QLabel("Ready — load a PCAP file to begin analysis")
        self.status_label.setFont(QFont(FONT_MONO, 8))
        self.status_label.setStyleSheet(f"color: {TEXT_MUTED}; background: transparent; border: none;")

        version = QLabel("v1.0.0  |  11 detectors active")
        version.setFont(QFont(FONT_MONO, 8))
        version.setStyleSheet(f"color: {TEXT_DIM}; background: transparent; border: none;")

        hl.addWidget(self.status_label)
        hl.addStretch()
        hl.addWidget(version)
        return bar

    # ── ACTIONS ─────────────────────────────────────────────────────────

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PCAP File", os.path.expanduser("~"),
            "All Files (*);;PCAP Files (*.pcap *.pcapng)"
        )
        if path:
            self.path_input.setText(path)

    def _run_analysis(self):
        path = self.path_input.text().strip()
        if not path:
            self._set_status("⚠  No file path provided", AMBER_WARN)
            return
        if not os.path.exists(path):
            self._set_status(f"✗  File not found: {path}", RED_ALERT)
            return

        self._clear_alerts()
        self.btn_analyze.setEnabled(False)
        self.btn_ai.setEnabled(False)
        self._set_status("Analyzing...", ACCENT_CYAN)

        self.thread = AnalysisThread(path)
        self.thread.status.connect(self._set_status_plain)
        self.thread.done.connect(self._on_analysis_done)
        self.thread.error.connect(self._on_analysis_error)
        self.thread.start()

    def _on_analysis_done(self, alerts):
        # Store parsed data so AI thread can use it
        self._last_packets         = self.thread.packets
        self._last_flow_table      = self.thread.flow_table
        self._last_source_activity = self.thread.source_activity
        self._pcap_loaded          = True

        self.btn_analyze.setEnabled(True)
        self.btn_ai.setEnabled(True)        # unlock AI button

        count = len(alerts)
        if count == 0:
            self._set_status("✓  Analysis complete — no threats detected", GREEN_OK)
            self._show_empty_state()
        else:
            auto  = sum(1 for a in alerts if a.get("tier") == "AUTO")
            human = sum(1 for a in alerts if a.get("tier") == "HUMAN")
            self._set_status(
                f"⚡  {count} alerts  |  {auto} auto-blocked  |  {human} require analyst decision",
                RED_ALERT if auto > 0 else AMBER_WARN
            )
            self.stats_label.setText(f"{count} alerts found")
            for alert in alerts:
                card = AlertCard(alert)
                self.alert_layout.insertWidget(self.alert_layout.count() - 1, card)

    def _on_analysis_error(self, error_msg):
        self.btn_analyze.setEnabled(True)
        self._set_status(f"✗  Error: {error_msg}", RED_ALERT)

    def _run_ai_analysis(self):
        if not self._pcap_loaded:
            self._set_status("⚠  Run Analyze first before requesting AI analysis", AMBER_WARN)
            return

        self.btn_ai.setEnabled(False)
        self.btn_analyze.setEnabled(False)
        self._set_status("◈  Sending capture to AI analyst...", ACCENT_CYAN)

        self.ai_thread = AIThread(
            self._last_packets,
            self._last_flow_table,
            self._last_source_activity
        )
        self.ai_thread.done.connect(self._on_ai_done)
        self.ai_thread.error.connect(self._on_ai_error)
        self.ai_thread.start()

    def _on_ai_done(self, report):
        self.btn_ai.setEnabled(True)
        self.btn_analyze.setEnabled(True)
        self._set_status("◈  AI analysis complete", ACCENT_CYAN)
        self.ai_window = AIReportWindow(report)
        self.ai_window.show()

    def _on_ai_error(self, error_msg):
        self.btn_ai.setEnabled(True)
        self.btn_analyze.setEnabled(True)
        self._set_status(f"✗  AI error: {error_msg}", RED_ALERT)

    def _clear_alerts(self):
        while self.alert_layout.count() > 1:
            item = self.alert_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.stats_label.setText("No file loaded")
        self._set_status("Ready — load a PCAP file to begin analysis", TEXT_MUTED)

    def _show_empty_state(self):
        lbl = QLabel("No threats detected in this capture")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setFont(QFont(FONT_UI, 13))
        lbl.setStyleSheet(
            f"color: {TEXT_MUTED}; background: transparent; border: none; padding: 60px;"
        )
        self.alert_layout.insertWidget(0, lbl)

    def _set_status(self, msg, color=None):
        self.status_label.setText(msg)
        self.status_label.setStyleSheet(
            f"color: {color or TEXT_MUTED}; background: transparent; border: none;"
        )

    def _set_status_plain(self, msg):
        self._set_status(msg, ACCENT_CYAN)


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  ENTRY POINT                                                         ║
# ╚══════════════════════════════════════════════════════════════════════╝
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ThreatDetectorApp()
    window.show()
    sys.exit(app.exec_())
