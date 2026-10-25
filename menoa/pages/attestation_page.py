"""
The Attestation page: checks system binaries against the attestation server's signed hashes, and lists every binary's status
"""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox

from menoa.utils.attestation_utils import get_number_of_binaries, get_binary_data, attest
from menoa.pages.progress_dialog import run_with_progress


class AttestationPage(QWidget):
    """
    A button to check the binaries, and a table of every binary in the attestation database
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Menoa - Attestation")
        self.layout = QVBoxLayout(self)

        # Top buttons
        button_layout = QHBoxLayout()
        self.button1 = QPushButton("Check System Binaries")
        self.button1.clicked.connect(self.run_attestation)

        button_layout.addWidget(self.button1)
        self.layout.addLayout(button_layout)

        # Table below
        self.table = QTableWidget()
        self.table.verticalHeader().setVisible(False)
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


    def run_attestation(self) -> None:
        """
        Checks every binary and shows the counts per status. Hashing ~2.5k binaries takes seconds, so it runs off the GUI thread
        """
        counts = {}
        failures = run_with_progress(lambda progress: counts.update(attest()) or [], "Checking system binaries...", "Attestation")
        if failures:
            QMessageBox.warning(self, "Attestation", "\n".join(failures))
        else:
            QMessageBox.information(self, "Attestation", "\n".join(f"{status}: {n}" for status, n in sorted(counts.items())))
        self.populate_table()

    def populate_table(self) -> None:
        """
        Fills the table from the attestation database
        """
        binary_data = get_binary_data()

        # Clear existing items and reset row count
        self.table.setRowCount(len(binary_data))

        for row, binary in enumerate(binary_data):
            # Each binary should be a tuple: (name, version, hash, checked_status)
            for col, value in enumerate(binary):
                item = QTableWidgetItem(str(value))
                self.table.setItem(row, col, item)