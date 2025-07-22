from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget, QListWidget, QListWidgetItem, QHBoxLayout, QStackedWidget, QLabel, QVBoxLayout, QPushButton, QTableWidget, QTableWidgetItem

from utils.attestation_utils import get_number_of_binaries, get_binary_data


def button_one_action():
    print("Button One Clicked!")

def button_two_action():
    print("Button Two Clicked!")

def get_table_cell_value(row, col):
    return f"R{row+1}C{col+1}"  # Dummy value, replace with real logic

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
        self.table.setRowCount(get_number_of_binaries())
        self.populate_table()
        self.layout.addWidget(self.table)

    def populate_table(self):
        data = get_binary_data()
        row1=1

        for row in range(self.table.rowCount()):
            for col in range(self.table.columnCount()):
                value = get_table_cell_value(row, col)
                item = QTableWidgetItem(value)
                self.table.setItem(row1, col, item)
