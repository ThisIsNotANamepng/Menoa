from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox, QApplication, QSizePolicy, QFileDialog
from PySide6.QtCore import Qt, QSize, QObject, Signal, Slot, QThread
from PySide6.QtGui import QPainter, QPen, QColor
import sys, os

from menoa.utils.clam_utils import get_scan_total, scan_path_streaming, get_last_time_scanned, get_database_version, set_last_time_scanned

class Scanner(QObject):
    progress = Signal(int)
    finished = Signal()
    log = Signal(str)

    def set_scan_path(self, path):
        self.scan_path = path

    def set_scan_type(self, scan_type):
        self.scan_type = scan_type

    @Slot()
    def scan(self):
        print(self.scan_type)
        total_files = get_scan_total(self.scan_path)
        tick_number = total_files / 1000 if total_files >= 1000 else 1

        scanned_files = ticked = last_ticked = 0

        for file, result in scan_path_streaming(self.scan_path, self.scan_type):
            self.log.emit(f"{file} {result}")

            scanned_files += 1
            if total_files >= 1000 and scanned_files - last_ticked >= tick_number:
                last_ticked = scanned_files
                ticked += 1
            else:
                ticked = min(ticked + (1000 / total_files), 1000)
            self.progress.emit(int(ticked))

        set_last_time_scanned()
        self.finished.emit()

class CircularProgress(QWidget):
    def __init__(self, parent=None, thickness=10):
        super().__init__(parent)
        self._value = 0
        self._min = 0
        self._max = 1000
        self._thickness = thickness
        self.setMinimumSize(QSize(150, 150))

    def setRange(self, minimum, maximum):
        self._min, self._max = minimum, maximum
        self.update()

    def setValue(self, val):
        self._value = val
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(self._thickness, self._thickness,
                                     -self._thickness, -self._thickness)
        start_angle = 90 * 16
        span_angle = -int(360 * 16 * (self._value - self._min) / (self._max - self._min))

        pen_bg = QPen(QColor(200,200,200), self._thickness)
        painter.setPen(pen_bg)
        painter.drawEllipse(rect)

        pen_fg = QPen(QColor(100,150,250), self._thickness)
        painter.setPen(pen_fg)
        painter.drawArc(rect, start_angle, span_angle)

        if self._value >= self._max:
            pen_check = QPen(QColor(0,180,0), self._thickness)
            pen_check.setCapStyle(Qt.RoundCap)
            painter.setPen(pen_check)
            w,h = self.width(), self.height()
            painter.drawLine(w*0.3, h*0.5, w*0.45, h*0.7)
            painter.drawLine(w*0.45, h*0.7, w*0.75, h*0.3)
        painter.end()

class ClamPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Menoa - Antivirus")
        self._setup_ui()
        self._load_db_info()

        # Paths for quick scan
        self._quick_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents")
        ]
        self._quick_index = 0

    def _setup_ui(self):
        # Progress circle
        self.circular = CircularProgress(thickness=12)
        self.circular.setRange(0, 1000)
        top = QGroupBox("ClamAV Antivirus")
        hl = QHBoxLayout()
        hl.addStretch()
        hl.addWidget(self.circular, alignment=Qt.AlignCenter)
        hl.addStretch()
        top.setLayout(hl)

        # Status labels
        self.status1 = QLabel()
        self.status2 = QLabel()
        for lbl in (self.status1, self.status2):
            lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        mid = QGroupBox()
        ml = QHBoxLayout()
        ml.addWidget(self.status1)
        ml.addWidget(self.status2)
        mid.setLayout(ml)

        # Buttons
        btns = QGroupBox()
        bl = QHBoxLayout()
        b1 = QPushButton("Quick Scan");   b1.clicked.connect(self.quick_scan)
        b2 = QPushButton("Scan Folder");  b2.clicked.connect(self.scan_folder)
        b3 = QPushButton("Scan File");    b3.clicked.connect(self.scan_file)
        b4 = QPushButton("Full Scan");    b4.clicked.connect(self.full_scan)
        for b in (b1, b2, b3, b4):
            bl.addWidget(b)
        btns.setLayout(bl)

        # Log
        self.log_box = QTextEdit(readOnly=True)

        # Layout
        mlayout = QVBoxLayout(self)
        mlayout.setContentsMargins(20,20,20,20)
        mlayout.setSpacing(10)
        mlayout.addWidget(top,    stretch=3)
        mlayout.addWidget(mid,    stretch=1)
        mlayout.addWidget(btns,   stretch=1)
        mlayout.addWidget(self.log_box, stretch=6)

    def _load_db_info(self):
        ver, changed = get_database_version()
        self.status1.setText(f"DB Patch: {ver}, Last changed: {changed}")
        self.status2.setText(f"Last scan: {get_last_time_scanned()}")

    def _start_scan(self, path, scan_type="standard"):
        """Helper to wire up a Scanner worker for a single path."""
        if getattr(self, 'scan_thread', None) and self.scan_thread.isRunning():
            return

        self.log_box.append(f"Starting scan: {path}")
        self.scan_worker = Scanner()
        self.scan_worker.set_scan_path(path)
        self.scan_worker.set_scan_type(scan_type)

        self.scan_thread = QThread()
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.scan)

        self.scan_worker.progress.connect(self.circular.setValue)
        self.scan_worker.progress.connect(lambda v: self.status1.setText(f"Progress: {v/10}%"))
        self.scan_worker.log.connect(self.log_box.append)

        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.finished.connect(self._load_db_info)
        self.scan_worker.finished.connect(lambda: self.status1.setText("Completed!"))
        self.scan_worker.finished.connect(lambda: self.status2.setText(f"Last scan: {get_last_time_scanned()}"))

        if scan_type == "quick":
            # If it's a quick scan check if there are any more quick scan paths to scan
            self.scan_worker.finished.connect(self._maybe_continue_quick)

        self.scan_thread.start()

    def _maybe_continue_quick(self):
        """If Quick Scan still has more paths, scan next."""
        if self._quick_index < len(self._quick_paths) - 1:
            self._quick_index += 1
            next_path = self._quick_paths[self._quick_index]
            self._start_scan(next_path, "quick")
        else:
            self._quick_index = 0

    @Slot()
    def quick_scan(self):
        self._quick_index = 0
        self._start_scan(self._quick_paths[0], "quick")

    @Slot()
    def scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self._start_scan(folder)

    @Slot()
    def scan_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if file:
            self._start_scan(file)

    @Slot()
    def full_scan(self):
        self._start_scan("/", "deep")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ClamPage()
    win.resize(600, 600)
    win.show()
    sys.exit(app.exec())
