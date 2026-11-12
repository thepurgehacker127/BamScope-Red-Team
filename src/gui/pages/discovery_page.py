"""
BamScope Red Team - Discovery Page
Full reconnaissance controls and results view.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QComboBox, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QAbstractItemView, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal

from network.interfaces import get_network_interfaces
from discovery.arp_scanner import arp_scan


class ScanWorker(QThread):
    """Runs the ARP scan in a background thread so the GUI stays responsive."""
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, target: str, interface: str):
        super().__init__()
        self.target = target
        self.interface = interface

    def run(self):
        try:
            results = arp_scan(self.target, interface=self.interface)
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))


class DiscoveryPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self._build_ui()
        self._load_interfaces()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 30, 36, 30)
        layout.setSpacing(0)

        title = QLabel("Discovery")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        subtitle = QLabel("Authorized network reconnaissance and host discovery.")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(subtitle)

        # ===== Controls Card =====
        controls_card = QFrame()
        controls_card.setObjectName("contentCard")
        controls_layout = QVBoxLayout(controls_card)
        controls_layout.setContentsMargins(24, 22, 24, 22)
        controls_layout.setSpacing(16)

        # Row 1
        row1 = QGridLayout()
        row1.setHorizontalSpacing(16)
        row1.setVerticalSpacing(10)

        iface_label = QLabel("Network Interface")
        iface_label.setStyleSheet("color: #8b98a5; font-size: 12px;")
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(220)

        target_label = QLabel("Target (CIDR / IP / Range)")
        target_label.setStyleSheet("color: #8b98a5; font-size: 12px;")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 192.168.1.0/24  or  10.0.0.1-50")
        self.target_input.setMinimumWidth(260)

        profile_label = QLabel("Scan Profile")
        profile_label.setStyleSheet("color: #8b98a5; font-size: 12px;")
        self.profile_combo = QComboBox()
        self.profile_combo.addItems([
            "Passive Discovery",
            "Standard Reconnaissance",
            "Detailed Asset Enumeration",
            "Service Discovery",
            "Authorized Security Assessment"
        ])
        self.profile_combo.setCurrentIndex(1)

        row1.addWidget(iface_label, 0, 0)
        row1.addWidget(self.interface_combo, 1, 0)
        row1.addWidget(target_label, 0, 1)
        row1.addWidget(self.target_input, 1, 1)
        row1.addWidget(profile_label, 0, 2)
        row1.addWidget(self.profile_combo, 1, 2)
        controls_layout.addLayout(row1)

        # Row 2
        row2 = QGridLayout()
        row2.setHorizontalSpacing(16)
        row2.setVerticalSpacing(10)

        timing_label = QLabel("Timing Template")
        timing_label.setStyleSheet("color: #8b98a5; font-size: 12px;")
        self.timing_combo = QComboBox()
        self.timing_combo.addItems([
            "T3 - Normal (Recommended)",
            "T2 - Polite",
            "T4 - Aggressive",
            "T1 - Sneaky",
            "T5 - Insane"
        ])

        exclude_label = QLabel("Exclude (comma separated)")
        exclude_label.setStyleSheet("color: #8b98a5; font-size: 12px;")
        self.exclude_input = QLineEdit()
        self.exclude_input.setPlaceholderText("e.g. 192.168.1.1, 192.168.1.254")

        row2.addWidget(timing_label, 0, 0)
        row2.addWidget(self.timing_combo, 1, 0)
        row2.addWidget(exclude_label, 0, 1)
        row2.addWidget(self.exclude_input, 1, 1)
        controls_layout.addLayout(row2)

        # Row 3
        row3 = QHBoxLayout()
        row3.setSpacing(12)

        self.start_btn = QPushButton("Start Discovery")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 18px;
                font-weight: 500;
            }
            QPushButton:hover { background-color: #2ea043; }
            QPushButton:disabled { background-color: #1f3d2a; color: #6b7785; }
        """)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #da3633;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 18px;
                font-weight: 500;
            }
            QPushButton:hover { background-color: #f85149; }
            QPushButton:disabled { background-color: #3d1f1f; color: #6b7785; }
        """)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1a2230;
                border: none;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #3b82f6;
                border-radius: 3px;
            }
        """)

        row3.addWidget(self.start_btn)
        row3.addWidget(self.stop_btn)
        row3.addSpacing(16)
        row3.addWidget(self.progress_bar, stretch=1)
        controls_layout.addLayout(row3)

        self.status_label = QLabel("Ready. Configure target and click Start Discovery.")
        self.status_label.setStyleSheet("color: #8b98a5; font-size: 12px; margin-top: 4px;")
        controls_layout.addWidget(self.status_label)

        layout.addWidget(controls_card)
        layout.addSpacing(20)

        # ===== Results Table =====
        results_card = QFrame()
        results_card.setObjectName("contentCard")
        results_layout = QVBoxLayout(results_card)
        results_layout.setContentsMargins(20, 18, 20, 18)

        results_title = QLabel("Discovered Hosts")
        results_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: 600;")
        results_layout.addWidget(results_title)
        results_layout.addSpacing(10)

        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels([
            "IP Address", "MAC Address", "Hostname", "Vendor", "Status", "Method"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background-color: #0b0f14;
                border: 1px solid #1a2230;
                border-radius: 8px;
                gridline-color: #1a2230;
            }
            QHeaderView::section {
                background-color: #0f141c;
                color: #8b98a5;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #1a2230;
                font-weight: 500;
            }
            QTableWidget::item {
                padding: 6px;
            }
        """)
        results_layout.addWidget(self.results_table)

        layout.addWidget(results_card)
        layout.addStretch()

        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self._on_stop)

    def _load_interfaces(self):
        self.interface_combo.clear()
        interfaces = get_network_interfaces()

        if not interfaces:
            self.interface_combo.addItem("No interfaces found")
            return

        for iface in interfaces:
            if iface["ip"] != "No IPv4":
                label = f"{iface['name']}  —  {iface['ip']}"
            else:
                label = f"{iface['name']}  —  No IPv4"
            self.interface_combo.addItem(label, userData=iface["name"])

        for i in range(self.interface_combo.count()):
            if "No IPv4" not in self.interface_combo.itemText(i):
                self.interface_combo.setCurrentIndex(i)
                break

    def _on_start(self):
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Please enter a target before starting.")
            self.status_label.setStyleSheet("color: #f85149; font-size: 12px;")
            return

        iface = self.interface_combo.currentData()
        if not iface:
            self.status_label.setText("Please select a valid network interface.")
            self.status_label.setStyleSheet("color: #f85149; font-size: 12px;")
            return

        # Clear previous results
        self.results_table.setRowCount(0)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(20)
        self.status_label.setText(f"Scanning {target} via ARP on {iface}...")
        self.status_label.setStyleSheet("color: #3b82f6; font-size: 12px;")

        # Start background worker
        self.worker = ScanWorker(target, iface)
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.error.connect(self._on_scan_error)
        self.worker.start()

    def _on_stop(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Discovery stopped by user.")
        self.status_label.setStyleSheet("color: #8b98a5; font-size: 12px;")

    def _on_scan_finished(self, results: list):
        self.progress_bar.setValue(100)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if not results:
            self.status_label.setText("Scan complete. No hosts found.")
            self.status_label.setStyleSheet("color: #8b98a5; font-size: 12px;")
            return

        for host in results:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            self.results_table.setItem(row, 0, QTableWidgetItem(host.get("ip", "")))
            self.results_table.setItem(row, 1, QTableWidgetItem(host.get("mac", "")))
            self.results_table.setItem(row, 2, QTableWidgetItem(host.get("hostname", "")))
            self.results_table.setItem(row, 3, QTableWidgetItem(host.get("vendor", "")))
            self.results_table.setItem(row, 4, QTableWidgetItem(host.get("status", "Up")))
            self.results_table.setItem(row, 5, QTableWidgetItem(host.get("method", "ARP")))

        self.status_label.setText(f"Scan complete. Found {len(results)} host(s).")
        self.status_label.setStyleSheet("color: #3fb950; font-size: 12px;")

    def _on_scan_error(self, message: str):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Error: {message}")
        self.status_label.setStyleSheet("color: #f85149; font-size: 12px;")
