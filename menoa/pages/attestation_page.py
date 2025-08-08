from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget, QListWidget, QListWidgetItem, QHBoxLayout, QStackedWidget, QLabel, QVBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView

from utils.attestation_utils import get_number_of_binaries, get_binary_data


def button_one_action():
    print("Button One Clicked!")

def button_two_action():
    print("Button Two Clicked!")


class AttestationPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Attestation Page")
        self.layout = QVBoxLayout(self)

        # Top buttons
        button_layout = QHBoxLayout()
        self.button1 = QPushButton("Button 1")
        self.button2 = QPushButton("Button 2")
        self.button1.clicked.connect(button_one_action)
        self.button2.clicked.connect(button_two_action)

        button_layout.addWidget(self.button1)
        button_layout.addWidget(self.button2)
        self.layout.addLayout(button_layout)

        # Table below
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Version", "Hash", "Status"])
        self.table.setRowCount(get_number_of_binaries())
        self.populate_table()
        self.layout.addWidget(self.table)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)


    def populate_table(self):
        binary_data = get_binary_data()

        # Clear existing items and reset row count
        self.table.setRowCount(len(binary_data))

        for row, binary in enumerate(binary_data):
            # Each binary should be a tuple: (name, version, hash, checked_status)
            for col, value in enumerate(binary):
                item = QTableWidgetItem(str(value))
                self.table.setItem(row, col, item)