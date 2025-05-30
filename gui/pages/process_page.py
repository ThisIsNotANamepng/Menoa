import sys
import time
import psutil

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QDoubleSpinBox, QPushButton, QTableWidget, QTableWidgetItem
from PySide6.QtCore import QTimer, QObject

from utils.process_utils import predict

# External placeholders
def get_model_version() -> str:
    ## Replace with actual version
    return "0.1.0"

class PredictionEngine(QObject):
    def __init__(self):
        print("engine started")

    def scan(self, threshold=0.6):
        # Does a scan, saves the results to a variable
        ## Get the threshold form the input box
        self.data = predict(threshold)
    
    def info(self, pid):
        # Returns the data from the lastest for a pid 

        if pid in self.data[0]:
            return self.data[1][self.data[0].index(pid)-1]
        else:
            return "Unscanned"

class ProcessPage(QWidget):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.setWindowTitle("Process Page")
        self.layout = QVBoxLayout(self)

        # Top row widgets
        top_layout = QHBoxLayout()

        # Model version label
        self.version_label = QLabel(f"Model version: {get_model_version()}")
        top_layout.addWidget(self.version_label)

        # Threshold input
        ## Need to incorporate this into scans and prpbably save it in a config somewhere so it can be used in background scans too
        self.threshold_label = QLabel("Threshold:")
        self.threshold_input = QDoubleSpinBox()
        self.threshold_input.setRange(0.0, 1.0)
        self.threshold_input.setSingleStep(0.01)
        self.threshold_input.setValue(0.5)
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
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "PID",
            "Command Line",
            "Up Time",
            "Memory (%)",
            "CPU (%)",
            "Extra Info",
        ])
        self.layout.addWidget(self.table)

        # Timer to refresh processes
        self.timer = QTimer()
        self.timer.timeout.connect(self.populate_table)
        self.timer.start(5000)  # Refresh every 5 seconds

        # Start en engine which scans and holds results
        engine = PredictionEngine()

        # Initial population
        self.populate_table()

    def on_scan(self):
        threshold = self.threshold_input.value()
        predict(threshold)

        self.engine.scan()

    def populate_table(self):

        engine = self.engine

        engine.scan()
        
        processes = list(psutil.process_iter(attrs=['pid', 'cmdline', 'create_time', 'memory_percent', 'cpu_percent']))
        self.table.setRowCount(len(processes))

        for row, proc in enumerate(processes):
            pid = proc.info['pid']
            cmd = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else proc.name()
            uptime_seconds = time.time() - proc.info['create_time']
            uptime_str = time.strftime("%H:%M:%S", time.gmtime(uptime_seconds))
            mem = proc.info['memory_percent']
            cpu = proc.info['cpu_percent']
            extra = engine.info(pid)

            self.table.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.table.setItem(row, 1, QTableWidgetItem(cmd))
            self.table.setItem(row, 2, QTableWidgetItem(uptime_str))
            self.table.setItem(row, 3, QTableWidgetItem(f"{mem:.1f}"))
            self.table.setItem(row, 4, QTableWidgetItem(f"{cpu:.1f}"))
            self.table.setItem(row, 5, QTableWidgetItem(extra))
