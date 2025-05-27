import sys
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget, QListWidget, QListWidgetItem, QHBoxLayout, QStackedWidget, QLabel, QVBoxLayout, QPushButton
from pages.network_page import NetworkPage
from pages.clam_page import ClamPage


# Placeholder classes for other pages

class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("This is the dashboard, I want to have a few rows, one for each tool. Each one has a title and info on the left, and a check or red x on the right for the status of the thing"))
        layout.addWidget(QPushButton("Scan"))
        self.setLayout(layout)

class ProcessPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Process Page"))
        layout.addWidget(QPushButton("Refresh"))
        self.setLayout(layout)

class AttestationPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Attestation Page"))
        layout.addWidget(QPushButton("Verify"))
        self.setLayout(layout)

class CommandPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Command Page"))
        layout.addWidget(QPushButton("Execute"))
        self.setLayout(layout)


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

        self.stack = QStackedWidget()
        self.stack.addWidget(DashboardPage()) # index 0
        self.stack.addWidget(ClamPage()) # index 1
        self.stack.addWidget(NetworkPage()) # index 2
        self.stack.addWidget(ProcessPage()) # index 3
        self.stack.addWidget(AttestationPage()) # index 4
        self.stack.addWidget(CommandPage()) # index 5

        layout = QHBoxLayout()
        layout.addWidget(self.menu_widget, 1)
        layout.addWidget(self.stack, 4)

        self.setLayout(layout)

        self.menu_widget.setCurrentRow(0)  # default to dashboard

    def display_page(self, index):
        self.stack.setCurrentIndex(index)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    w = MainWidget()
    w.setWindowTitle("System Manager")
    w.resize(1000, 700)
    w.show()

    try:
        with open("style.qss", "r") as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        pass  # optional stylesheet

    sys.exit(app.exec())
