from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox
from PySide6.QtCore import QTimer
from PySide6.QtGui import QFont, QFontDatabase

from menoa.utils import network_utils
from menoa.utils.network_utils import number_of_threats, get_interface_summary, reload_endpoints, get_feed_summary
from concurrent.futures import ProcessPoolExecutor

class NetworkPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Menoa - Network Scanning")

        # --- Top Left Box ---
        self.top_box = QGroupBox("Network Status")
        self.status_label = QLabel(number_of_threats())
        self.status_label.setFont(QFont("Arial", 14, QFont.Bold))
        #self.status_label.setStyleSheet("color: #D32F2F; margin: 5px 0;")

        self.refresh_button = QPushButton("↻ Refresh")
        self.refresh_button.setMinimumWidth(100)
        self.refresh_button.clicked.connect(self.handle_refresh)

        top_layout = QVBoxLayout()
        top_layout.setSpacing(12)
        top_layout.setContentsMargins(12, 24, 12, 12)
        top_layout.addWidget(self.status_label)
        top_layout.addWidget(self.refresh_button, 0)
        self.top_box.setLayout(top_layout)

        # --- Bottom Left Box ---
        self.bottom_box = QTextEdit()
        self.bottom_box.setReadOnly(True)
        self.bottom_box.setText(get_interface_summary()+get_feed_summary())
        self.bottom_box.setStyleSheet("font-family: Consolas;")

        # --- Right Side Box (with title and proper spacing) ---
        self.log_group = QGroupBox("Real-time Activity Log")  # Added title
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(QFont("Consolas", 10))  # Monospace font for column alignment
        self.log_box.setLineWrapMode(QTextEdit.NoWrap)  # Prevent line wrapping

        log_layout = QVBoxLayout()
        log_layout.addWidget(self.log_box)
        self.log_group.setLayout(log_layout)

        # Timer for real-time updates
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_logs)
        self.timer.start(1000)

        # Process executor for blocking network scans. We use a single-worker
        # ProcessPoolExecutor so heavy work runs in a separate process and
        # doesn't freeze the GUI. We poll the future from the Qt timer and
        # update the widgets when the result is ready.
        self.executor = ProcessPoolExecutor(max_workers=1)
        self._future = None

        # --- Layout ---
        left_layout = QVBoxLayout()
        left_layout.setSpacing(10)
        left_layout.addWidget(self.top_box, 1)
        left_layout.addWidget(self.bottom_box, 2)

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        main_layout.addLayout(left_layout, 1)
        main_layout.addWidget(self.log_group, 2)  # Now wrapped in titled group box

    def handle_refresh(self):
        reload_endpoints()
        self.status_label.setText(number_of_threats())
        self.bottom_box.setText(get_interface_summary()+get_feed_summary())
        # Add visual feedback
        self.refresh_button.setText("✓ Refreshed")
        QTimer.singleShot(1000, lambda: self.refresh_button.setText("↻ Refresh"))

    def update_logs(self):
        # Submit a background process if none is running. If one is running,
        # poll it and update UI when it's finished. This prevents overlapping
        # scans and keeps the GUI responsive.
        if self._future is None:
            # Submit the process task. Use the module-level function so it
            # can be pickled by the ProcessPoolExecutor.
            try:
                self._future = self.executor.submit(network_utils.connections_check)
            except Exception as e:
                # If submission fails, show the error in the log box.
                self.log_box.setText(f"Error starting background scan: {e}")
                self._future = None
            return

        # If a future exists, check if it's done and update the UI with the
        # returned logs. We call result only when done() is True so this is
        # non-blocking.
        if self._future.done():
            try:
                logs = self._future.result()
            except Exception as e:
                logs = f"Error in background scan: {e}"

            formatted_logs = []
            formatted_logs.append("PID   Remote address")
            for line in str(logs).split('\n'):
                formatted_logs.append(line)

            self.log_box.setText('\n'.join(formatted_logs))
            # Clear future so next timeout will start a new run
            self._future = None


    def closeEvent(self, event):
        """Ensure background executor is shutdown when the widget closes."""
        try:
            self.timer.stop()
            if hasattr(self, 'executor') and self.executor:
                # Shutdown without waiting for long-running child process to finish
                self.executor.shutdown(wait=False)
        except Exception:
            pass
        return super().closeEvent(event)



