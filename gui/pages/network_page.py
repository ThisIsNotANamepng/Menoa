from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox
from PySide6.QtCore import QTimer
from utils.network_tools import number_of_threats, get_interface_summary, get_realtime_logs, reload_endpoints

class NetworkPage(QWidget):
    def __init__(self):
        super().__init__()

        # --- Top Left Box ---
        self.top_box = QGroupBox("Network Info")
        self.status_label = QLabel(number_of_threats())
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.handle_refresh)

        top_layout = QVBoxLayout()
        top_layout.addWidget(self.status_label)
        top_layout.addWidget(self.refresh_button)
        self.top_box.setLayout(top_layout)

        # --- Bottom Left Box ---
        self.bottom_box = QTextEdit()
        self.bottom_box.setReadOnly(True)
        self.bottom_box.setText(get_interface_summary())

        # --- Right Side Box ---
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)

        # Timer for real-time updates
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_logs)
        self.timer.start(1000)  # update every second

        # --- Layout ---
        left_layout = QVBoxLayout()
        left_layout.addWidget(self.top_box)
        left_layout.addWidget(self.bottom_box)

        main_layout = QHBoxLayout()
        main_layout.addLayout(left_layout, 1)
        main_layout.addWidget(self.log_box, 2)

        self.setLayout(main_layout)

    def handle_refresh(self):
        reload_endpoints()
        self.status_label.setText(number_of_threats())
        self.bottom_box.setText(get_interface_summary())

    def update_logs(self):
        self.log_box.setText(get_realtime_logs())
        self.log_box.moveCursor(self.log_box.textCursor().End)  # scroll to bottom
