from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox, QApplication, QSizePolicy
from PySide6.QtCore import Qt, QTimer, QSize, QObject, Signal, Slot, QThread
from PySide6.QtGui import QPainter, QPen, QColor
import sys, time

from utils.clam_utils import get_scan_total, scan_path_streaming, get_last_time_scanned, get_database_version, set_last_time_scanned


# Class for interacting with scanning utilities
class Scanner(QObject):
    progress = Signal(int)
    finished = Signal()
    log = Signal(str)

    @Slot()
    def scan(self, path="/home/jack/Downloads/yarafy_rules"):

        total_files = get_scan_total(path)

        print("Total files to scan: ", total_files)

        # The progress bar has a total of 1000, we need to know when to tick 1 for that 1000, that's the total number of files to scan / 1000
        ## When the number to scan is les than 1000 it shits the bed
        tick_number = total_files // 1000 if total_files >= 1000 else 1
        scanned_files = 0

        # How many times the progress bar has ticked forward
        ticked = 0

        # The string that is displayed in the log box on the bottom
        logs = ""

        for file, result in scan_path_streaming(path):
            print(file, result)
            logs = (file + " " + result)
            self.log.emit(logs)

            scanned_files+=1

            if scanned_files % tick_number == 0:
                ticked += 1
                self.progress.emit(ticked)

        self.finished.emit()
        set_last_time_scanned()

# External status function (unchanged)
def external_update_status():
    return ["Status line 1", "Status line 2", "Status line 3"]

def external_update_progress():
    # retained for any other updates
    return 0

def external_button_action(index):
    print(f"Button {index} pressed")

class CircularProgress(QWidget):
    def __init__(self, parent=None, thickness=10):
        super().__init__(parent)
        self._value = 0
        self._min = 0
        self._max = 1000
        self._thickness = thickness
        self.setMinimumSize(QSize(150, 150))

    def setRange(self, minimum, maximum):
        self._min = minimum
        self._max = maximum
        self.update()

    def setValue(self, val):
        self._value = val
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(self._thickness, self._thickness,
                                     -self._thickness, -self._thickness)
        start_angle = 90 * 16
        span_angle = -int(360 * 16 * (self._value - self._min) / (self._max - self._min))

        # Background circle
        pen_bg = QPen(QColor(200, 200, 200), self._thickness)
        painter.setPen(pen_bg)
        painter.drawEllipse(rect)

        # Progress arc
        pen_fg = QPen(QColor(100, 150, 250), self._thickness)
        painter.setPen(pen_fg)
        painter.drawArc(rect, start_angle, span_angle)
        
        # If complete, draw check
        if self._value >= self._max:
            pen_check = QPen(QColor(0, 180, 0), self._thickness)
            pen_check.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen_check)
            w, h = self.width(), self.height()
            painter.drawLine(w*0.3, h*0.5, w*0.45, h*0.7)
            painter.drawLine(w*0.45, h*0.7, w*0.75, h*0.3)
        painter.end()

class ClamPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Circular Progress Window")

        # --- Top Group Box ---
        self.top_box = QGroupBox("ClamAV Antivirus")
        self.top_box.setObjectName("clamGroupBox")
        self.circular = CircularProgress(thickness=12)
        self.circular.setRange(0, 1000)

        top_layout = QHBoxLayout()
        top_layout.addStretch(1)
        top_layout.addWidget(self.circular, 0, Qt.AlignmentFlag.AlignCenter)
        top_layout.addStretch(1)
        self.top_box.setLayout(top_layout)


        # --- Status Group Box ---
        self.mid_box = QGroupBox()
        #status_layout = QVBoxLayout()
        status_layout = QHBoxLayout()
        self.status_labels = [QLabel() for _ in range(3)]

        for lbl in self.status_labels:
            lbl.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            status_layout.addWidget(lbl)
        self.mid_box.setLayout(status_layout)

        for i in range(2):
            self.status_labels[i].setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.status_labels[i].setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            status_layout.addWidget(self.status_labels[i])

        #self.status_labels[0].setText(f"Progress: {v}%")
        version = get_database_version()
        self.status_labels[0].setText(f"Patch: {version[0]}, Last changed: {version[1]}")
        self.status_labels[0].setObjectName("clamAVDatabaseVersion")

        self.status_labels[1].setText(f"Last scan: {get_last_time_scanned()}")
        self.status_labels[1].setObjectName("clamAVLastScanned")


        # --- Buttons Box ---
        self.btn_box = QGroupBox()
        btn_layout = QHBoxLayout()
        # Button 1 starts filling
        self.start_button = QPushButton("Start Progress")
        self.start_button.clicked.connect(self.start_fill)
        btn_layout.addWidget(self.start_button)
        # Buttons 2 & 3 external actions
        for i, text in enumerate(["Action 2", "Action 3"], start=2):
            btn = QPushButton(text)
            btn.clicked.connect(lambda _, x=i: external_button_action(x))
            btn_layout.addWidget(btn)
        self.btn_box.setLayout(btn_layout)

        # --- Log Box ---
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)

        # --- Main Layout ---
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        main_layout.addWidget(self.top_box, stretch=3)
        main_layout.addWidget(self.mid_box, stretch=1)
        main_layout.addWidget(self.btn_box, stretch=1)
        main_layout.addWidget(self.log_box, stretch=6)

        # Placeholder for worker/thread
        self.thread = None
        self.worker = None        

    # Updates the log box
    @Slot(str)
    def append_log(self, text):
        self.log_box.insertPlainText(text + "\n")
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())

    def start_fill(self):
        # Prevent multiple threads
        if self.thread and self.thread.isRunning():
            return

        # Setup worker
        self.worker = Scanner()
        self.thread = QThread()
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.thread.started.connect(self.worker.scan)
        self.worker.progress.connect(self.circular.setValue)
        self.worker.progress.connect(lambda v: self.status_labels[0].setText(f"Progress: {v}%"))
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(lambda: self.status_labels[0].setText("Completed!"))
        self.worker.finished.connect(lambda: self.status_labels[1].setText(f"Last scan: {get_last_time_scanned()}"))

        version = get_database_version()
        self.worker.finished.connect(lambda: self.status_labels[0].setText(f"Patch: {version[0]}, Last changed: {version[1]}"))

        # Connect log box
        self.log_box.insertPlainText("Loading signatures...")
        self.worker.log.connect(self.append_log)

        # Start
        self.thread.start()
