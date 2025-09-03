import sys
import time
import psutil

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QDoubleSpinBox, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QStatusBar
from PySide6.QtCore import QTimer, QObject, QDateTime
from PySide6.QtGui import QFont, QFontDatabase, QColor

from menoa.utils.process_utils import predict, get_process_threshold, set_process_threshold, get_model_version

class PredictionEngine(QObject):
    def __init__(self):
        super().__init__()
        print("Engine started")
        self.data = ([], [])  # Initialize empty data structure

    def scan(self, threshold=0.6):
        """Perform scan and store results"""
        self.data = predict(threshold)

    def info(self, pid):
        """Get prediction info for specific PID"""
        try:
            idx = self.data[0].index(pid)
            return self.data[1][idx]
        except (ValueError, IndexError):
            return "Unscanned"

class ProcessPage(QWidget):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.setWindowTitle("Menoa - Process Scanning")
        self.layout = QVBoxLayout(self)

        # Top row widgets
        top_layout = QHBoxLayout()

        # Model version label
        self.version_label = QLabel(f"Model version: {get_model_version()}")
        top_layout.addWidget(self.version_label)

        # Threshold input
        ## Need to incorporate this into scans and probably save it in a config somewhere so it can be used in background scans too
        self.threshold_label = QLabel("Threshold:")
        self.threshold_input = QDoubleSpinBox()
        self.threshold_input.setRange(0.0, 1.0)
        self.threshold_input.setSingleStep(0.01)
        self.threshold_input.setValue(get_process_threshold())
        top_layout.addWidget(self.threshold_label)
        top_layout.addWidget(self.threshold_input)

        # Scan button
        ## Right now this runs a scan but doesn't write those results to the table, need to hook that in
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.on_scan)
        top_layout.addWidget(self.scan_button)

        self.layout.addLayout(top_layout)

        # Table for process log
        self.table = QTableWidget()
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "PID",
            "Command Line",
            "Up Time",
            "Memory (%)",
            "CPU (%)",
            "Classification",
        ])
        self.layout.addWidget(self.table)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # PID column
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Time column
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Time column
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Time column
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Time column

        # Timer to refresh processes
        self.timer = QTimer()
        self.timer.timeout.connect(self.populate_table)
        self.timer.start(10000000) # This freezes the app so I'm just going to make it not run anymore

        # Start en engine which scans and holds results
        engine = PredictionEngine()

        # Initial population
        self.populate_table()

    def on_scan(self):
        threshold = self.threshold_input.value()
        set_process_threshold(threshold) # The threshold is changed in the global config.toml when the 'scan' button is hit, change it to then the user changes the threshold at all
        self.engine.scan(threshold)
        self.populate_table()

    def populate_table(self):
        processes = list(psutil.process_iter(attrs=[
            'pid', 'cmdline', 'create_time', 'memory_percent', 'cpu_percent'
        ]))

        self.table.setRowCount(len(processes))
        current_time = time.time()

        for row, proc in enumerate(processes):
            try:
                pid = proc.info['pid']
                cmd = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else proc.name()
                uptime = time.strftime("%H:%M:%S", time.gmtime(current_time - proc.info['create_time']))
                mem = proc.info['memory_percent']
                cpu = proc.info['cpu_percent']
                threat = self.engine.info(pid)

                # Apply threat-based styling
                threat_item = QTableWidgetItem(threat)
                if "malicious" in threat.lower():
                    threat_item.setForeground(QColor(220, 53, 69))
                    threat_item.setFont(QFont("Arial", weight=QFont.Bold))
                elif "suspicious" in threat.lower():
                    threat_item.setForeground(QColor(255, 143, 0))

                self.table.setItem(row, 0, QTableWidgetItem(str(pid)))
                self.table.setItem(row, 1, QTableWidgetItem(cmd))
                self.table.setItem(row, 2, QTableWidgetItem(uptime))
                self.table.setItem(row, 3, QTableWidgetItem(f"{mem:.1f}"))
                self.table.setItem(row, 4, QTableWidgetItem(f"{cpu:.1f}"))
                self.table.setItem(row, 5, threat_item)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Resize columns after population
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)