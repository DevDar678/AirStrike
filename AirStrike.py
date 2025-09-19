#!/usr/bin/env python3
"""
AirStrike - A comprehensive WiFi security analysis tool
- Tab 1: Scan Networks (AP table)
- Tab 2: Packet Capture: enter filename, start/stop capture, live CLI-like output,
         and a Stations table showing clients.
- Tab 3: Deauthentication: send deauth packets to selected AP/client
- Tab 4: Aircrack-ng: crack WiFi passwords using captured files
Notes:
- Run as root (airodump-ng requires elevated permissions).
- Make sure your interface (wlan0mon) is correct.
"""

import sys
import re
import os
import signal
from collections import OrderedDict
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLineEdit, QLabel,
    QMessageBox, QTabWidget, QTextEdit, QSizePolicy, QHeaderView, QSpinBox,
    QFileDialog, QCheckBox, QStyleFactory
)
from PyQt5.QtCore import QProcess, Qt, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon


MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class AirodumpTool(QWidget):
    def __init__(self, iface="wlan0mon"):
        super().__init__()
        self.iface = iface
        
        # Apply dark theme
        self.set_dark_theme()
        
        self.setWindowTitle("AirStrike")
        self.setGeometry(100, 50, 1600, 1000)  # Larger window for better visibility

        # Set application font
        app_font = QFont("Lucida Sans", 12)  # Use Optima if available, fallback to system font
        app_font.setBold(True)
        QApplication.setFont(app_font)

        # Main layout with vertical tabs on the left
        main_layout = QHBoxLayout()
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.West)  # Vertical tabs on the left
        self.tabs.setStyleSheet("""
             QTabWidget::pane {
                border: 2px solid #1e3e5a;
                background: #1a1a1a;
            }
            QTabBar::tab {
                background: #2c2c2c;
                color: #dcdcdc;
                padding: 14px;
                margin: 2px;
                border-radius: 8px;
                font-weight: bold;
                min-width: 50px;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #0e4d92, stop:1 #1e3e5a);
                color: #00ff7f;
                border: 2px solid #00ff7f;
            }
            QTabBar::tab:hover {
                background: #333344;
                color: #00d4ff;
            }
        """)

        # Icons for tabs (similar to WiFi-Pumpkin style)
        self.scan_tab = QWidget()
        self.capture_tab = QWidget()
        self.deauth_tab = QWidget()
        self.crack_tab = QWidget()

        self.tabs.addTab(self.scan_tab, QIcon.fromTheme("view-refresh"), "Scan Networks")
        self.tabs.addTab(self.capture_tab, QIcon.fromTheme("media-record"), "Packet Capture")
        self.tabs.addTab(self.deauth_tab, QIcon.fromTheme("dialog-cancel"), "Deauthentication")
        self.tabs.addTab(self.crack_tab, QIcon.fromTheme("system-lock-screen"), "Aircrack-ng")

        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        # Enhanced button style with shadows, borders, and larger size
        self.button_style = """
             QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #141e30, stop:1 #243b55);
                color: #e2e2df;
                border: 2px solid #1e3e5a;
                border-radius: 12px;
                padding: 12px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #243b55, stop:1 #141e30);
                border: 2px solid #00e0ff;
                color: #00e0ff;
            }
            QPushButton:pressed {
                background: #0e4d92;
                border: 2px solid #00ff7f;
            }
            QPushButton:disabled {
                background: #444;
                color: #888;
                border: 2px dashed #555;
            }
        """

        # ---------------- Scan Tab UI ----------------
        scan_layout = QVBoxLayout()

        btn_row = QHBoxLayout()
        self.scan_button = QPushButton("Scan Networks")
        self.scan_button.setFixedHeight(60)
        self.scan_button.setStyleSheet(self.button_style)
        self.scan_button.clicked.connect(self.run_airodump_scan)
        btn_row.addWidget(self.scan_button)

        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.setFixedHeight(60)
        self.stop_scan_button.setStyleSheet(self.button_style)
        self.stop_scan_button.clicked.connect(self.stop_process_graceful)
        btn_row.addWidget(self.stop_scan_button)

        self.start_capture_from_scan_btn = QPushButton("Start Capture (Selected)")
        self.start_capture_from_scan_btn.setFixedHeight(60)
        self.start_capture_from_scan_btn.setStyleSheet(self.button_style)
        self.start_capture_from_scan_btn.clicked.connect(self.start_capture_from_scan)
        btn_row.addWidget(self.start_capture_from_scan_btn)

        btn_row.addStretch()
        scan_layout.addLayout(btn_row)

        # AP table (Scan)
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(
            ["BSSID", "PWR", "Beacons", "Data", "CH", "MB", "ENC", "CIPHER", "ESSID"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        header = self.table.horizontalHeader()
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 80)
        self.table.setColumnWidth(4, 60)
        self.table.setColumnWidth(5, 80)
        self.table.setColumnWidth(6, 80)
        self.table.setColumnWidth(7, 100)
        self.table.setColumnWidth(8, 300)
        self.table.setStyleSheet("""
            QTableWidget {
                gridline-color: #555555;
                font-size: 15px;
                background-color: #1a1a1a;
            }
            QTableWidget::item {
                border: 1px solid #555555;
                padding: 5px;
                color: #00ff00;
            }
            QTableWidget::item:selected {
                background-color: #4286f4;
                color: white;
            }
            QHeaderView::section {
                background-color: #2b5278;
                color: white;
                padding: 5px;
                border: 1px solid #1e3e5a;
                font-weight: bold;
            }
        """)
        scan_layout.addWidget(self.table)

        self.scan_tab.setLayout(scan_layout)

        # ---------------- Capture Tab UI ----------------
        capture_layout = QVBoxLayout()

        filename_row = QHBoxLayout()
        self.filename_label = QLabel("Enter file name for capture (no extension):")
        self.filename_label.setFont(QFont("Optima", 12, QFont.Bold))
        filename_row.addWidget(self.filename_label)
        self.filename_input = QLineEdit()
        self.filename_input.setFont(QFont("Optima", 12))
        self.filename_input.setPlaceholderText("e.g. testCapture")
        filename_row.addWidget(self.filename_input)
        capture_layout.addLayout(filename_row)

        capture_buttons = QHBoxLayout()
        self.capture_start_button = QPushButton("Start Capture")
        self.capture_start_button.setFixedHeight(50)
        self.capture_start_button.setStyleSheet(self.button_style)
        self.capture_start_button.clicked.connect(self.start_capture)
        capture_buttons.addWidget(self.capture_start_button)

        self.capture_stop_button = QPushButton("Stop Capture")
        self.capture_stop_button.setFixedHeight(50)
        self.capture_stop_button.setStyleSheet(self.button_style)
        self.capture_stop_button.clicked.connect(self.stop_capture)
        capture_buttons.addWidget(self.capture_stop_button)

        self.capture_back_to_scan_btn = QPushButton("Back to Scan Tab")
        self.capture_back_to_scan_btn.setFixedHeight(50)
        self.capture_back_to_scan_btn.setStyleSheet(self.button_style)
        self.capture_back_to_scan_btn.clicked.connect(self.return_to_scan)
        capture_buttons.addWidget(self.capture_back_to_scan_btn)

        capture_buttons.addStretch()
        capture_layout.addLayout(capture_buttons)

        self.capture_output = QTextEdit()
        self.capture_output.setReadOnly(True)
        self.capture_output.setFontFamily("Lucida Sans")
        self.capture_output.setFontPointSize(12)
        self.capture_output.setLineWrapMode(QTextEdit.NoWrap)
        self.capture_output.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff00;
                border: 2px solid #2b5278;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        capture_layout.addWidget(self.capture_output, stretch=3)

        self.stations_table = QTableWidget()
        self.stations_table.setColumnCount(7)
        self.stations_table.setHorizontalHeaderLabels(
            ["BSSID", "STATION", "PWR", "Rate", "Lost", "Frames", "Notes/Probes"]
        )
        self.stations_table.verticalHeader().setVisible(False)
        self.stations_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.stations_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.stations_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stations_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #555555;
                font-size: 12px;
                background-color: #1a1a1a;
            }
            QTableWidget::item {
                border: 1px solid #555555;
                padding: 5px;
                color: #00ff00;
            }
            QTableWidget::item:selected {
                background-color: #4286f4;
                color: white;
            }
            QHeaderView::section {
                background-color: #2b5278;
                color: white;
                padding: 5px;
                border: 1px solid #1e3e5a;
                font-weight: bold;
            }
        """)
        capture_layout.addWidget(self.stations_table, stretch=1)

        self.capture_tab.setLayout(capture_layout)

        # ---------------- Deauthentication Tab ----------------
        deauth_layout = QVBoxLayout()
        
        bssid_row = QHBoxLayout()
        bssid_label = QLabel("Target BSSID:")
        bssid_label.setFont(QFont("Optima", 12, QFont.Bold))
        bssid_row.addWidget(bssid_label)
        self.bssid_input = QLineEdit()
        self.bssid_input.setFont(QFont("Optima", 12))
        self.bssid_input.setPlaceholderText("Select from scan tab or enter manually")
        bssid_row.addWidget(self.bssid_input)
        
        self.get_bssid_btn = QPushButton("Get from Selected Network")
        self.get_bssid_btn.setFixedHeight(50)
        self.get_bssid_btn.setStyleSheet(self.button_style)
        self.get_bssid_btn.clicked.connect(self.get_selected_bssid)
        bssid_row.addWidget(self.get_bssid_btn)
        deauth_layout.addLayout(bssid_row)
        
        client_row = QHBoxLayout()
        client_label = QLabel("Client MAC (optional):")
        client_label.setFont(QFont("Optima", 12, QFont.Bold))
        client_row.addWidget(client_label)
        self.client_input = QLineEdit()
        self.client_input.setFont(QFont("Optima", 12))
        self.client_input.setPlaceholderText("00:11:22:33:44:55 (leave empty for broadcast)")
        client_row.addWidget(self.client_input)
        
        self.get_client_btn = QPushButton("Get from Selected Client")
        self.get_client_btn.setFixedHeight(50)
        self.get_client_btn.setStyleSheet(self.button_style)
        self.get_client_btn.clicked.connect(self.get_selected_client)
        client_row.addWidget(self.get_client_btn)
        deauth_layout.addLayout(client_row)
        
        count_row = QHBoxLayout()
        count_label = QLabel("Number of deauth packets:")
        count_label.setFont(QFont("Optima", 12, QFont.Bold))
        count_row.addWidget(count_label)
        self.deauth_count = QSpinBox()
        self.deauth_count.setFont(QFont("Optima", 12))
        self.deauth_count.setRange(0, 1000000)
        self.deauth_count.setValue(1000)
        self.deauth_count.setSpecialValueText("Infinite (0)")
        count_row.addWidget(self.deauth_count)
        deauth_layout.addLayout(count_row)
        
        iface_row = QHBoxLayout()
        iface_label = QLabel("Monitor interface:")
        iface_label.setFont(QFont("Optima", 12, QFont.Bold))
        iface_row.addWidget(iface_label)
        self.deauth_iface_input = QLineEdit()
        self.deauth_iface_input.setFont(QFont("Optima", 12))
        self.deauth_iface_input.setText(self.iface)
        iface_row.addWidget(self.deauth_iface_input)
        deauth_layout.addLayout(iface_row)
        
        # Deauth buttons row
        deauth_buttons = QHBoxLayout()
        self.deauth_button = QPushButton("Send Deauthentication Packets")
        self.deauth_button.setFixedHeight(50)
        self.deauth_button.setStyleSheet(self.button_style)
        self.deauth_button.clicked.connect(self.send_deauth)
        deauth_buttons.addWidget(self.deauth_button)
        
        # Add Stop Deauth button
        self.stop_deauth_button = QPushButton("Stop Deauth Attack")
        self.stop_deauth_button.setFixedHeight(50)
        self.stop_deauth_button.setStyleSheet(self.button_style)
        self.stop_deauth_button.clicked.connect(self.stop_deauth_process)
        deauth_buttons.addWidget(self.stop_deauth_button)
        
        deauth_layout.addLayout(deauth_buttons)
        
        self.deauth_output = QTextEdit()
        self.deauth_output.setReadOnly(True)
        self.deauth_output.setFontFamily("Monospace")
        self.deauth_output.setFontPointSize(12)
        self.deauth_output.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff00;
                border: 2px solid #2b5278;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        deauth_layout.addWidget(self.deauth_output)
        
        self.deauth_tab.setLayout(deauth_layout)

        # ---------------- Aircrack-ng Tab ----------------
        crack_layout = QVBoxLayout()
        
        cap_file_row = QHBoxLayout()
        cap_file_label = QLabel("Capture file (.cap):")
        cap_file_label.setFont(QFont("Optima", 12, QFont.Bold))
        cap_file_row.addWidget(cap_file_label)
        self.cap_file_input = QLineEdit()
        self.cap_file_input.setFont(QFont("Optima", 12))
        self.cap_file_input.setPlaceholderText("Select a .cap file")
        cap_file_row.addWidget(self.cap_file_input)
        self.browse_cap_btn = QPushButton("Browse")
        self.browse_cap_btn.setFixedHeight(50)
        self.browse_cap_btn.setStyleSheet(self.button_style)
        self.browse_cap_btn.clicked.connect(self.browse_cap_file)
        cap_file_row.addWidget(self.browse_cap_btn)
        crack_layout.addLayout(cap_file_row)
        
        wordlist_row = QHBoxLayout()
        wordlist_label = QLabel("Wordlist file:")
        wordlist_label.setFont(QFont("Optima", 12, QFont.Bold))
        wordlist_row.addWidget(wordlist_label)
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setFont(QFont("Optima", 12))
        self.wordlist_input.setText("/usr/share/wordlists/rockyou.txt")
        wordlist_row.addWidget(self.wordlist_input)
        self.browse_wordlist_btn = QPushButton("Browse")
        self.browse_wordlist_btn.setFixedHeight(50)
        self.browse_wordlist_btn.setStyleSheet(self.button_style)
        self.browse_wordlist_btn.clicked.connect(self.browse_wordlist_file)
        wordlist_row.addWidget(self.browse_wordlist_btn)
        self.use_default_wordlist = QCheckBox("Use rockyou.txt")
        self.use_default_wordlist.setFont(QFont("Optima", 12, QFont.Bold))
        self.use_default_wordlist.setChecked(True)
        self.use_default_wordlist.stateChanged.connect(self.toggle_wordlist)
        wordlist_row.addWidget(self.use_default_wordlist)
        crack_layout.addLayout(wordlist_row)
        
        bssid_crack_row = QHBoxLayout()
        bssid_crack_label = QLabel("BSSID (optional):")
        bssid_crack_label.setFont(QFont("Optima", 12, QFont.Bold))
        bssid_crack_row.addWidget(bssid_crack_label)
        self.bssid_crack_input = QLineEdit()
        self.bssid_crack_input.setFont(QFont("Optima", 12))
        self.bssid_crack_input.setPlaceholderText("Leave empty to try all networks")
        bssid_crack_row.addWidget(self.bssid_crack_input)
        self.get_bssid_crack_btn = QPushButton("Get from Selected Network")
        self.get_bssid_crack_btn.setFixedHeight(50)
        self.get_bssid_crack_btn.setStyleSheet(self.button_style)
        self.get_bssid_crack_btn.clicked.connect(self.get_selected_bssid_crack)
        bssid_crack_row.addWidget(self.get_bssid_crack_btn)
        crack_layout.addLayout(bssid_crack_row)
        
        crack_buttons = QHBoxLayout()
        self.crack_button = QPushButton("Start Cracking")
        self.crack_button.setFixedHeight(50)
        self.crack_button.setStyleSheet(self.button_style)
        self.crack_button.clicked.connect(self.start_cracking)
        crack_buttons.addWidget(self.crack_button)
        
        self.stop_crack_button = QPushButton("Stop Cracking")
        self.stop_crack_button.setFixedHeight(50)
        self.stop_crack_button.setStyleSheet(self.button_style)
        self.stop_crack_button.clicked.connect(self.stop_cracking)
        crack_buttons.addWidget(self.stop_crack_button)
        crack_buttons.addStretch()
        crack_layout.addLayout(crack_buttons)
        
        self.crack_output = QTextEdit()
        self.crack_output.setReadOnly(True)
        self.crack_output.setFontFamily("Monospace")
        self.crack_output.setFontPointSize(12)
        self.crack_output.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff00;
                border: 2px solid #2b5278;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        crack_layout.addWidget(self.crack_output)
        
        self.crack_tab.setLayout(crack_layout)

        # ---------------- Process & state ----------------
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.read_output)
        self.process.readyReadStandardError.connect(self.read_output)
        self.process.finished.connect(self.on_process_finished)
        
        self.deauth_process = QProcess(self)
        self.deauth_process.readyReadStandardOutput.connect(self.read_deauth_output)
        self.deauth_process.readyReadStandardError.connect(self.read_deauth_output)
        
        self.crack_process = QProcess(self)
        self.crack_process.readyReadStandardOutput.connect(self.read_crack_output)
        self.crack_process.readyReadStandardError.connect(self.read_crack_output)

        self.access_points = OrderedDict()
        self.stations = OrderedDict()
        self.mode = "idle"
        
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_tables)
        self.update_timer.start(500)

        self.output_buffer = ""
        self.last_output_update = 0

    def set_dark_theme(self):
        """Apply a dark theme to the application"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        QApplication.setPalette(dark_palette)
        QApplication.setStyle(QStyleFactory.create("Fusion"))
        
        font = QFont("Optima", 12, QFont.Bold)
        QApplication.setFont(font)

    @staticmethod
    def strip_ansi(s: str) -> str:
        return re.sub(r'\x1B\[[0-9;]*[A-Za-z]', '', s)

    def on_process_finished(self, exitCode, exitStatus):
        if self.mode == "capture":
            self.capture_output.append(f"\n[INFO] Process finished (exit code {exitCode}).")
        elif self.mode == "scan":
            pass
        self.mode = "idle"
        
    def stop_deauth_process(self, clear_output: bool = False):
        """
        Stop the aireplay-ng deauth process. Attempt SIGINT first (graceful),
        then fall back to terminate(), and finally kill() if necessary.

        If clear_output is True, the deauth output QTextEdit is cleared after stopping.
        """
        pid = self.deauth_process.processId()
        if pid:
            # Try sending SIGINT first for a graceful stop (aireplay-ng will exit nicely)
            try:
                os.kill(pid, signal.SIGINT)
                # wait briefly for orderly shutdown
                if not self.deauth_process.waitForFinished(3000):
                    # SIGINT didn't finish it — try terminate() then kill()
                    self.deauth_process.terminate()
                    if not self.deauth_process.waitForFinished(2000):
                        self.deauth_process.kill()
            except Exception:
                # Fallback if os.kill fails (e.g., permission or process already dead)
                try:
                    self.deauth_process.terminate()
                    if not self.deauth_process.waitForFinished(2000):
                        self.deauth_process.kill()
                except Exception:
                    # Last-resort: nothing else we can do reliably
                    pass
        else:
            # no pid; still ensure Qt process object stopped
            if self.deauth_process.state() != QProcess.NotRunning:
                try:
                    self.deauth_process.terminate()
                    if not self.deauth_process.waitForFinished(2000):
                        self.deauth_process.kill()
                except Exception:
                    pass

        # Update UI
        if clear_output:
            self.deauth_output.clear()
        else:
            self.deauth_output.append("\n[INFO] Deauth attack stopped.")

                
    def stop_crack_process(self):
        if self.crack_process.state() != QProcess.NotRunning:
            self.crack_process.terminate()
            if not self.crack_process.waitForFinished(2000):
                self.crack_process.kill()

    def stop_process_graceful(self):
        pid = self.process.processId()
        if pid:
            try:
                os.kill(pid, signal.SIGINT)
            except Exception as e:
                try:
                    self.process.terminate()
                except Exception:
                    self.process.kill()
        else:
            pass

    def run_airodump_scan(self):
        self.access_points.clear()
        self.stations.clear()
        self.update_ap_table()
        self.update_stations_table()
        self.capture_output.clear()

        if self.process.state() != QProcess.NotRunning:
            try:
                self.process.kill()
            except Exception:
                pass

        self.mode = "scan"
        self.process.start("airodump-ng", [self.iface])

    def parse_ap_line(self, parts):
        bssid = parts[0]
        pwr = parts[1] if len(parts) > 1 else ""
        beacons = parts[2] if len(parts) > 2 else ""
        data = parts[3] if len(parts) > 3 else ""
        ch = parts[5] if len(parts) > 5 else ""
        mb = parts[6] if len(parts) > 6 else ""
        enc = parts[7] if len(parts) > 7 else ""
        cipher = parts[8] if len(parts) > 8 else ""
        essid = " ".join(parts[9:]) if len(parts) > 9 else (" ".join(parts[8:]) if len(parts) > 8 else "")
        return {
            "BSSID": bssid,
            "PWR": pwr,
            "Beacons": beacons,
            "Data": data,
            "CH": ch,
            "MB": mb,
            "ENC": enc,
            "CIPHER": cipher,
            "ESSID": essid
        }

    def update_ap_table(self):
        self.table.setRowCount(len(self.access_points))
        for row, (bssid, ap) in enumerate(self.access_points.items()):
            for col, key in enumerate(["BSSID", "PWR", "Beacons", "Data", "CH", "MB", "ENC", "CIPHER", "ESSID"]):
                item = QTableWidgetItem(ap.get(key, ""))
                item.setTextAlignment(Qt.AlignCenter)
                item.setForeground(QColor(0, 255, 0))
                self.table.setItem(row, col, item)

    def update_stations_table(self):
        self.stations_table.setRowCount(len(self.stations))
        for row, ((station_mac, bssid), st) in enumerate(self.stations.items()):
            vals = [
                bssid,
                station_mac,
                st.get("PWR", ""),
                st.get("Rate", ""),
                st.get("Lost", ""),
                st.get("Frames", ""),
                st.get("Notes", "")
            ]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(str(v))
                item.setTextAlignment(Qt.AlignCenter)
                item.setForeground(QColor(0, 255, 0))
                self.stations_table.setItem(row, col, item)

    def parse_station_line(self, parts):
        bssid = parts[0]
        station = parts[1] if len(parts) > 1 else ""
        pwr = parts[2] if len(parts) > 2 else ""
        rate = parts[3] if len(parts) > 3 else ""
        lost = parts[4] if len(parts) > 4 else ""
        frames = parts[5] if len(parts) > 5 else ""
        notes = " ".join(parts[6:]) if len(parts) > 6 else ""
        return bssid, station, {"PWR": pwr, "Rate": rate, "Lost": lost, "Frames": frames, "Notes": notes}

    def read_output(self):
        raw_stdout = self.process.readAllStandardOutput().data().decode(errors="ignore")
        raw_stderr = self.process.readAllStandardError().data().decode(errors="ignore")
        raw = raw_stdout + ("\n" + raw_stderr if raw_stderr else "")
        clean = self.strip_ansi(raw)
        self.output_buffer += clean

    def update_tables(self):
        if not self.output_buffer:
            return
            
        if self.mode == "scan":
            for line in self.output_buffer.splitlines():
                line = line.rstrip()
                if not line:
                    continue
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 9 and MAC_RE.match(parts[0]):
                    ap = self.parse_ap_line(parts)
                    self.access_points[ap["BSSID"]] = ap
            self.update_ap_table()

        elif self.mode == "capture":
            self.capture_output.setPlainText(self.output_buffer)
            new_stations = OrderedDict()
            for line in self.output_buffer.splitlines():
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 2 and MAC_RE.match(parts[0]) and MAC_RE.match(parts[1]):
                    bssid, station, stinfo = self.parse_station_line(parts)
                    key = (station, bssid)
                    new_stations[key] = stinfo
            for key, info in new_stations.items():
                if key in self.stations:
                    self.stations[key].update(info)
                else:
                    self.stations[key] = info
            self.update_stations_table()

        self.output_buffer = ""
            
    def read_deauth_output(self):
        raw = self.deauth_process.readAllStandardOutput().data().decode(errors="ignore")
        raw_err = self.deauth_process.readAllStandardError().data().decode(errors="ignore")
        clean = self.strip_ansi(raw + ("\n" + raw_err if raw_err else ""))
        self.deauth_output.append(clean)
        
    def read_crack_output(self):
        raw = self.crack_process.readAllStandardOutput().data().decode(errors="ignore")
        raw_err = self.crack_process.readAllStandardError().data().decode(errors="ignore")
        clean = self.strip_ansi(raw + ("\n" + raw_err if raw_err else ""))
        self.crack_output.append(clean)

    def start_capture_from_scan(self):
        sel = self.table.currentRow()
        if sel < 0:
            QMessageBox.warning(self, "Select AP", "Please select an AP from the scan table first.")
            return
        bssid = self.table.item(sel, 0).text()
        essid = self.table.item(sel, 8).text()
        safe = re.sub(r'[^A-Za-z0-9_\-]', '_', essid.strip())[:30] or "capture"
        self.filename_input.setText(safe)
        self.tabs.setCurrentWidget(self.capture_tab)

    def start_capture(self):
        sel = self.table.currentRow()
        if sel < 0:
            QMessageBox.warning(self, "No Network Selected", "Please select a WiFi network in Scan tab before starting capture.")
            return

        bssid = self.table.item(sel, 0).text()
        ch = self.table.item(sel, 4).text().strip()
        if not ch:
            QMessageBox.warning(self, "Missing Channel", "Selected AP has no channel information.")
            return

        fname = self.filename_input.text().strip()
        if not fname:
            QMessageBox.warning(self, "Missing Filename", "Please enter a filename in the Capture tab (no extension).")
            return

        filename = fname if fname.endswith(".cap") else fname + ".cap"

        if self.process.state() != QProcess.NotRunning:
            try:
                self.process.kill()
            except Exception:
                pass

        self.capture_output.clear()
        self.stations.clear()
        self.update_stations_table()
        self.output_buffer = ""

        self.mode = "capture"
        self.tabs.setCurrentWidget(self.capture_tab)

        argv = ["-w", filename, "--bssid", bssid, "-c", ch, self.iface]
        self.capture_output.append(f"[INFO] Starting capture for BSSID {bssid} on channel {ch}")
        self.capture_output.append(f"[INFO] Writing base file: {filename}\n")
        self.process.start("airodump-ng", argv)

    def stop_capture(self):
        if self.mode != "capture":
            QMessageBox.information(self, "Not Capturing", "There is no active capture to stop.")
            return

        pid = self.process.processId()
        if pid:
            try:
                os.kill(pid, signal.SIGINT)
                self.capture_output.append("\n[INFO] Sent SIGINT to airodump-ng (stopping capture gracefully)...")
            except Exception as e:
                try:
                    self.process.terminate()
                    self.capture_output.append("\n[WARN] Could not send SIGINT; terminated process.")
                except Exception:
                    try:
                        self.process.kill()
                        self.capture_output.append("\n[WARN] Could not terminate; killed process.")
                    except Exception:
                        self.capture_output.append(f"\n[ERROR] Failed to stop process: {e}")
        else:
            if self.process.state() != QProcess.NotRunning:
                self.process.terminate()

        self.mode = "idle"
        self.capture_output.append("\n[INFO] Capture stopped. Airodump-ng should have written .cap and related files.")
        QMessageBox.information(self, "Capture Stopped", "Capture stopped. Check current directory for the .cap file(s).")

    def return_to_scan(self):
        if self.mode == "capture":
            self.stop_capture()
        self.tabs.setCurrentWidget(self.scan_tab)
        
    def get_selected_bssid(self):
        sel = self.table.currentRow()
        if sel < 0:
            QMessageBox.warning(self, "No Selection", "Select a network from the Scan tab first.")
            return
        bssid = self.table.item(sel, 0).text()
        self.bssid_input.setText(bssid)
        
    def get_selected_client(self):
        sel = self.stations_table.currentRow()
        if sel < 0:
            QMessageBox.warning(self, "No Selection", "Select a client from the Capture tab first.")
            return
        client_mac = self.stations_table.item(sel, 1).text()
        self.client_input.setText(client_mac)
            
    def send_deauth(self):
        bssid = self.bssid_input.text().strip()
        client_mac = self.client_input.text().strip()
        count = self.deauth_count.value()
        iface = self.deauth_iface_input.text().strip()
        
        if not bssid or not MAC_RE.match(bssid):
            QMessageBox.warning(self, "Invalid BSSID", "Enter a valid BSSID (MAC address).")
            return
            
        if client_mac and not MAC_RE.match(client_mac):
            QMessageBox.warning(self, "Invalid Client MAC", "Enter a valid client MAC address or leave empty for broadcast.")
            return
            
        if not iface:
            QMessageBox.warning(self, "Missing Interface", "Enter a monitor mode interface.")
            return
            
        cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
        if client_mac:
            cmd.extend(["-c", client_mac])
        cmd.append(iface)
        
        self.stop_deauth_process()
        
        self.deauth_output.clear()
        self.deauth_output.append(f"Starting deauthentication attack...\n")
        self.deauth_output.append(f"Command: {' '.join(cmd)}\n")
        self.deauth_process.start(cmd[0], cmd[1:])
        
    def browse_cap_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Capture File", "", "Capture Files (*.cap)")
        if filename:
            self.cap_file_input.setText(filename)
            
    def browse_wordlist_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Wordlist File", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            self.wordlist_input.setText(filename)
            
    def toggle_wordlist(self, state):
        if state == Qt.Checked:
            self.wordlist_input.setText("/usr/share/wordlists/rockyou.txt")
            self.wordlist_input.setEnabled(False)
        else:
            self.wordlist_input.setEnabled(True)
            
    def get_selected_bssid_crack(self):
        sel = self.table.currentRow()
        if sel < 0:
            QMessageBox.warning(self, "No Selection", "Select a network from the Scan tab first.")
            return
        bssid = self.table.item(sel, 0).text()
        self.bssid_crack_input.setText(bssid)
            
    def start_cracking(self):
        cap_file = self.cap_file_input.text().strip()
        wordlist = self.wordlist_input.text().strip()
        bssid = self.bssid_crack_input.text().strip()
        
        if not cap_file:
            QMessageBox.warning(self, "Missing File", "Select a .cap file first.")
            return
            
        if not os.path.exists(cap_file):
            QMessageBox.warning(self, "File Not Found", f"Capture file not found: {cap_file}")
            return
            
        if not wordlist:
            QMessageBox.warning(self, "Missing Wordlist", "Select a wordlist file first.")
            return
            
        if not os.path.exists(wordlist):
            QMessageBox.warning(self, "File Not Found", f"Wordlist file not found: {wordlist}")
            return
            
        if bssid and not MAC_RE.match(bssid):
            QMessageBox.warning(self, "Invalid BSSID", "Enter a valid BSSID or leave empty.")
            return
            
        cmd = ["aircrack-ng", "-w", wordlist]
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(cap_file)
        
        self.stop_crack_process()
        
        self.crack_output.clear()
        self.crack_output.append(f"Starting password cracking...\n")
        self.crack_output.append(f"Command: {' '.join(cmd)}\n")
        self.crack_process.start(cmd[0], cmd[1:])
        
    def stop_cracking(self):
        self.stop_crack_process()
        self.crack_output.append("\nCracking stopped by user.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AirodumpTool()
    window.show()
    sys.exit(app.exec_())
