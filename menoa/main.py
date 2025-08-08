import sys
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget, QListWidget, QListWidgetItem, QHBoxLayout, QStackedWidget, QLabel, QVBoxLayout, QStyle, QPushButton
from PySide6.QtGui import QDesktopServices, QCursor
from PySide6.QtCore import QUrl

from pages.network_page import NetworkPage
from pages.clam_page import ClamPage
from pages.attestation_page import AttestationPage
from pages.process_page import ProcessPage, PredictionEngine
from pages.script_page import ScriptPage

class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout()

        tools = [
            ("Clam", "Frontend for ClamAV, an open source malware scanner.", "ClamAV is an open-source antivirus engine for detecting trojans, viruses, malware, and other malicious threats.", "https://docs.example.com/clam"),
            ("Network", "Checks network connections against a list of known bad endpoints.", "Compares all outgoing IP address requests against a compiled list of known malware hosts and botnets.", "https://docs.example.com/network"),
            ("Process", "Classifies all current system processes as benign or malicious.", "Uses a machine learning model to check for malicious system processes using a homemade machine learning model.", "https://docs.example.com/process"),
            ("Attestation", "Validates system binary integrity.", "Performs attestation checks using hashes of local binaries against a server with known good hashes of binaries to detect malicious tampering of local software.", "https://docs.example.com/attestation"),
            ("Command", "Parses inputted Bash.", "Parses an inputted Bash script, predicting what effects will happen on the system if run.", "https://docs.example.com/command")
        ]

        for title, info, description, link in tools:
            row_container = QWidget()
            row_layout = QHBoxLayout()
            row_layout.setAlignment(Qt.AlignLeft)

            text_container = QWidget()
            text_layout = QVBoxLayout()

            lbl_title = QLabel(f"<b>{title}</b>")
            lbl_info = QLabel(info)
            lbl_description = QLabel(description)

            lbl_link = QLabel(f'<a href="{link}">Learn more</a>')
            lbl_link.setOpenExternalLinks(True)
            lbl_link.setTextInteractionFlags(Qt.TextBrowserInteraction)
            lbl_link.setCursor(QCursor(Qt.PointingHandCursor))

            for widget in [lbl_title, lbl_info, lbl_description, lbl_link]:
                widget.setObjectName("dashboardLabel")
                text_layout.addWidget(widget)

            text_container.setLayout(text_layout)
            row_layout.addWidget(text_container)

            icon_label = QLabel()
            if self.get_tool_status(title.lower()):
                icon = self.style().standardIcon(QStyle.SP_DialogApplyButton)
            else:
                icon = self.style().standardIcon(QStyle.SP_DialogCancelButton)
            pixmap = icon.pixmap(24, 24)
            icon_label.setPixmap(pixmap)
            row_layout.addWidget(icon_label, alignment=Qt.AlignVCenter)

            row_container.setLayout(row_layout)
            row_container.setObjectName("dashboardRow")
            main_layout.addWidget(row_container)

        self.setLayout(main_layout)

    def get_tool_status(self, tool_name: str) -> bool:
        # TODO: implement actual status checks
        return False

class MainWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.menu_widget = QListWidget()
        self.menu_widget.setFixedWidth(150)

        menu_items = ["Dashboard", "Clam", "Network", "Process", "Attestation", "Command"]
        for item in menu_items:
            list_item = QListWidgetItem(item)
            list_item.setTextAlignment(Qt.AlignCenter)
            self.menu_widget.addItem(list_item)

        self.menu_widget.currentRowChanged.connect(self.display_page)

        engine = PredictionEngine()

        self.stack = QStackedWidget()
        self.stack.addWidget(DashboardPage()) # index 0
        self.stack.addWidget(ClamPage()) # index 1
        self.stack.addWidget(NetworkPage()) # index 2
        self.stack.addWidget(ProcessPage(engine)) # index 3
        self.stack.addWidget(AttestationPage()) # index 4
        self.stack.addWidget(ScriptPage()) # index 5

        layout = QHBoxLayout()
        layout.addWidget(self.menu_widget, 1)
        layout.addWidget(self.stack, 3)

        self.setLayout(layout)

        self.menu_widget.setCurrentRow(0)  # default to dashboard

    def display_page(self, index):
        self.stack.setCurrentIndex(index)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    w = MainWidget()
    w.setWindowTitle("System Manager")
    w.resize(300, 100)
    w.show()

    QApplication.styleHints().colorSchemeChanged.connect(
        lambda scheme: app.setStyleSheet(load_theme(scheme))
    )

    if QApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark:
        # System is in dark mode
        with open("dark_style.qss", "r") as f:
            app.setStyleSheet(f.read())
    else:
        # System is in light mode
        with open("light_style.qss", "r") as f:
            app.setStyleSheet(f.read())


    sys.exit(app.exec())
