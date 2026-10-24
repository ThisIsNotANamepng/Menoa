from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox, QApplication, QSizePolicy, QFileDialog, QMessageBox
from PySide6.QtCore import Qt, QSize, QObject, Signal, Slot, QThread
from PySide6.QtGui import QPainter, QPen, QColor
import sys, os

from menoa.utils.clam_utils import get_scan_total, scan_path_streaming, result_kind, get_last_time_scanned, get_database_version, set_last_time_scanned, database_freshness, update_all_feeds
from menoa.pages.progress_dialog import run_with_progress

class Scanner(QObject):
    progress = Signal(int)
    finished = Signal()
    status = Signal(str)  # Final result text, emitted after finished so it isn't overwritten by finished's handlers
    log = Signal(str)

    def set_scan_path(self, path):
        self.scan_path = path

    @Slot()
    def scan(self):
        total_files = max(get_scan_total(self.scan_path), 1)
        scanned_files = last_value = 0
        infected = problems = 0

        try:
            for file, result in scan_path_streaming(self.scan_path):
                kind = result_kind(file, result)
                infected += kind == "infected"
                problems += kind == "error"
                self.log.emit(f"{file} {result}" if file else result)
                if not file:
                    continue

                scanned_files += 1
                # Progress is in tenths of a percent, held below 100% until clamscan actually finishes
                value = min(scanned_files * 1000 // total_files, 999)
                if value != last_value:
                    last_value = value
                    self.progress.emit(value)
        except Exception as e:
            self.log.emit(f"SCAN FAILED: {e}")
            self.finished.emit()
            self.status.emit("Scan failed, files were NOT checked (see log)")
            return

        set_last_time_scanned()
        self.progress.emit(1000)
        self.finished.emit()
        summary = f"{infected} threat(s) found" if infected else "No threats found"
        if problems:
            summary += f", {problems} item(s) couldn't be scanned"
        self.status.emit(f"Completed: {summary}")

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

        # Signature age, with a way to update them right here
        self.db_age = QLabel()
        update_button = QPushButton("Update now"); update_button.clicked.connect(self.update_databases)
        age = QGroupBox()
        al = QHBoxLayout()
        al.addWidget(self.db_age, stretch=1)
        al.addWidget(update_button)
        age.setLayout(al)

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
        mlayout.addWidget(age,    stretch=1)
        mlayout.addWidget(btns,   stretch=1)
        mlayout.addWidget(self.log_box, stretch=6)

    def _load_db_info(self):
        ver, changed = get_database_version()
        self.status1.setText(f"DB Patch: {ver}, Last changed: {changed}")
        self.status2.setText(f"Last scan: {get_last_time_scanned()}")

        state, text = database_freshness()
        color = {"fresh": "#4CAF50", "outdated": "#FF9800"}.get(state, "#F44336")
        if state == "critical":
            text += ", scans will miss newer malware"
        elif state in ("missing", "unreadable"):
            text += ", scans can't run until they're downloaded"
        self.db_age.setText(text)
        self.db_age.setStyleSheet(f"color: {color};")

    @Slot()
    def update_databases(self):
        failures = run_with_progress(lambda progress: update_all_feeds(progress) or [], "Updating malware signatures...")
        if failures:
            QMessageBox.warning(self, "Menoa", "Updating the malware signatures failed:\n\n" + "\n".join(failures))
        self._load_db_info()

    def _start_scan(self, path, scan_type="standard"):
        """Helper to wire up a Scanner worker for a single path."""
        if getattr(self, 'scan_thread', None) and self.scan_thread.isRunning():
            return

        self.log_box.append(f"Starting scan: {path}")
        self.scan_worker = Scanner()
        self.scan_worker.set_scan_path(path)

        self.scan_thread = QThread()
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.scan)

        self.scan_worker.progress.connect(self.circular.setValue)
        self.scan_worker.progress.connect(self._show_progress)
        self.scan_worker.log.connect(self.log_box.append)

        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.finished.connect(self._load_db_info)  # Also updates "Last scan"
        self.scan_worker.status.connect(self.status1.setText)

        if scan_type == "quick":
            # If it's a quick scan check if there are any more quick scan paths to scan
            self.scan_worker.finished.connect(self._maybe_continue_quick)

        self.scan_thread.start()

    @Slot(int)
    def _show_progress(self, value):
        self.status1.setText(f"Progress: {value / 10}%")

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
