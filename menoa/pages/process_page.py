"""
The Process page: lists running processes and classifies them with the process model
"""

import threading
import time
import psutil

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QDoubleSpinBox, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtCore import QTimer, QObject, Signal, Slot
from PySide6.QtGui import QFont, QColor

from menoa import theme
from menoa.utils.process_utils import predict, get_process_threshold, set_process_threshold, get_model_version, get_model_settings, is_unsigned_model

class PredictionEngine(QObject):
    """
    Holds the last scan's predictions, so the table can show each process's classification
    """

    def __init__(self) -> None:
        super().__init__()
        self.data = ([], [])  # Initialize empty data structure

    def scan(self, threshold: float = 0.6) -> None:
        """
        Scans the running processes and keeps the results, see process_utils.predict()
        """
        self.data = predict(threshold)

    def info(self, pid: int) -> str:
        """
        Returns the last scan's prediction for a PID, "Unscanned" if it wasn't in the scan
        """
        try:
            idx = self.data[0].index(pid)
            return self.data[1][idx]
        except (ValueError, IndexError):
            return "Unscanned"

class ProcessPage(QWidget):
    """
    The model version and threshold, a scan button, and a table of running processes with their classification
    """

    model_loaded = Signal(str)  # The model's version, or "unavailable"

    def __init__(self, engine: PredictionEngine) -> None:
        super().__init__()
        self.engine = engine
        self.setWindowTitle("Menoa - Process Scanning")
        self.layout = QVBoxLayout(self)

        # Top row widgets
        top_layout = QHBoxLayout()

        # Filled in by reload_model() once the window is open, loading the model takes over a second
        self.version_label = QLabel()
        top_layout.addWidget(self.version_label)

        # Someone who can edit config.toml could swap in their own model, so a model that isn't checked is always pointed out
        self.model_warning = QLabel()
        self.model_warning.setStyleSheet(f"color: {theme.COLORS['warning']};")
        self.model_warning.setWordWrap(True)

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
        self.layout.addWidget(self.model_warning)

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

        self.model_loaded.connect(self._show_model)  # A bound method, so it runs on the GUI thread
        self.reload_model()

    def reload_model(self) -> None:
        """
        Loads the model in the background and shows its version, and warns if it's an unsigned model. Called again when Settings changes the model
        """
        try:
            settings = get_model_settings()
            self.model_warning.setText(f"Using your own unsigned model: {settings['model_url']}" if is_unsigned_model(settings) else "")
        except Exception:
            self.model_warning.setText("")
        self.model_warning.setVisible(bool(self.model_warning.text()))

        self.version_label.setText("Model version: loading...")
        self.scan_button.setEnabled(False)  # Until the model is loaded, so a first run doesn't install it twice at once
        threading.Thread(target=self._load_model, daemon=True).start()

    def _load_model(self) -> None:
        """
        Loads the model on a background thread for its version, then emits model_loaded. A missing model shouldn't stop the GUI from opening
        """
        try:
            version = str(get_model_version())
        except Exception as e:
            print(f"Process model unavailable: {e}")
            version = "unavailable"
        self.model_loaded.emit(version)

    @Slot(str)
    def _show_model(self, version: str) -> None:
        """
        Shows the model's version and enables scanning
        """
        self.version_label.setText(f"Model version: {version}")
        self.scan_button.setEnabled(True)

    def on_scan(self) -> None:
        """
        Saves the threshold, scans with it and refreshes the table
        """
        threshold = self.threshold_input.value()
        set_process_threshold(threshold) # The threshold is changed in the global config.toml when the 'scan' button is hit, change it to then the user changes the threshold at all
        self.engine.scan(threshold)
        self.populate_table()

    def populate_table(self) -> None:
        """
        Fills the table with the running processes and the last scan's classifications
        """
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
                    threat_item.setForeground(QColor(theme.COLORS["bad"]))
                    threat_item.setFont(QFont("Arial", weight=QFont.Bold))
                elif "suspicious" in threat.lower():
                    threat_item.setForeground(QColor(theme.COLORS["warning"]))

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