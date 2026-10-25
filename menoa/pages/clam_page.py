from PySide6.QtWidgets import (QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox, QApplication, QSizePolicy, QFileDialog,
                               QMessageBox, QComboBox, QDialog, QDialogButtonBox, QListWidget, QListWidgetItem)
from PySide6.QtCore import Qt, QSize, QRect, QObject, Signal, Slot, QThread
from PySide6.QtGui import QPainter, QPen, QColor
import sys, os, time

from menoa.utils.clam_utils import get_scan_total, scan_path_streaming, result_kind, get_last_time_scanned, get_database_version, set_last_time_scanned, database_freshness, update_all_feeds
import menoa.utils.yara_utils as yara_utils
from menoa.utils.clam_utils import list_feeds as clam_feeds
from menoa.utils.utils import feeds_by_engine, FEED_LEVELS
from menoa.pages.progress_dialog import run_with_progress

ENGINES = {"clam": "ClamAV", "yara": "YARA"}

class Scanner(QObject):
    """
    Scans paths with one engine, "clam" or "yara". A scan with both runs two Scanners side by side
    """
    progress = Signal(int)
    finished = Signal()
    status = Signal(str)  # Final result text, emitted after finished so it isn't overwritten by finished's handlers
    log = Signal(str)

    def __init__(self, engine="clam", feeds=None, level=None):
        super().__init__()
        self.engine = engine
        self.feeds, self.level = feeds, level  # Which feeds to scan with, see utils.select_feeds()

    def set_scan_path(self, *paths):
        # Quick scans check several folders one after another
        self.scan_paths = paths

    @Slot()
    def scan(self):
        clam = self.engine == "clam"
        name = ENGINES[self.engine]
        stream = scan_path_streaming if clam else yara_utils.scan_path_streaming
        count = get_scan_total if clam else yara_utils.count_files
        label = "" if clam else "YARA: "  # ClamAV's lines look like they always have
        scanned_files = last_value = 0
        last_count = 0.0
        infected = problems = 0

        stages = []

        def on_progress(stage, done, total):
            # Before any file is scanned clamscan loads and compiles its signatures and YARA-X compiles its rules, which takes seconds
            if stage not in stages:
                stages.append(stage)
                self.log.emit(f"{stage}...")
            self.status.emit(f"{stage}: {min(done / total, 1):.0%}" if total else f"{stage}...")

        def on_summary(summary):
            rules = f"{int(summary.get('Known viruses', 0)):,} signatures" if clam else f"{int(summary.get('YARA rules', 0)):,} YARA rules"
            data = f" ({summary['Data scanned']})" if "Data scanned" in summary else ""
            self.log.emit(f"{name}: scanned {summary.get('Scanned files', '?')} files{data} with {rules} in {summary.get('Time', '?').split(' (')[0]}")

        try:
            total_files = max(sum(count(path) for path in self.scan_paths), 1)
            for path in self.scan_paths:
                for file, result in stream(path, on_progress, on_summary, self.feeds, self.level):
                    kind = result_kind(file, result)
                    infected += kind == "infected"
                    problems += kind == "error"
                    # YARA's clean files aren't logged, so a scan with both engines doesn't list every file twice
                    if clam or kind != "clean":
                        self.log.emit(f"{label}{file} {result}" if file else label + result)
                    if not file:
                        continue

                    scanned_files += 1
                    # Progress is in tenths of a percent, held below 100% until the engine actually finishes
                    value = min(scanned_files * 1000 // total_files, 999)
                    if value != last_value:
                        last_value = value
                        self.progress.emit(value)
                    # A big folder takes minutes to reach 0.1%, so the count shows it's moving (a few times a second, not per file)
                    if time.monotonic() - last_count > 0.25:
                        last_count = time.monotonic()
                        self.status.emit(f"Scanned {scanned_files:,} of {total_files:,} files")
        except Exception as e:
            self.log.emit(f"{name} SCAN FAILED: {e}")
            self.finished.emit()
            self.status.emit("Scan failed, files were NOT checked (see log)")
            return

        if clam:
            set_last_time_scanned()
        self.progress.emit(1000)
        self.finished.emit()
        summary = f"{infected} threat(s) found" if infected else "No threats found"
        if problems:
            summary += f", {problems} item(s) couldn't be scanned"
        self.status.emit(f"Completed: {summary}")

class CircularProgress(QWidget):
    """
    Two rings, ClamAV's progress inside and YARA's outside, each None when that engine isn't part of the scan
    The middle shows the average of the engines that are scanning, and a check mark once they've all finished
    """
    COLORS = {"clam": QColor(76, 175, 80), "yara": QColor(214, 58, 196)}

    def __init__(self, parent=None, thickness=10):
        super().__init__(parent)
        self._values = {"clam": None, "yara": None}  # None until a scan starts, so an idle circle shows no percentage
        self._max = 1000
        self._thickness = thickness
        self.setMinimumSize(QSize(180, 180))

    def start(self, engines):
        # Clears the last scan's rings and check mark
        self._values = {engine: 0 if engine in engines else None for engine in self._values}
        self.update()

    def setValue(self, value, engine="clam"):
        self._values[engine] = value
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        t = self._thickness
        side = min(self.width(), self.height())
        outer = QRect((self.width() - side) // 2, (self.height() - side) // 2, side, side).adjusted(t, t, -t, -t)
        inner = outer.adjusted(t * 2, t * 2, -t * 2, -t * 2)

        for engine, rect in (("yara", outer), ("clam", inner)):
            painter.setPen(QPen(QColor(200, 200, 200), t))
            painter.drawEllipse(rect)
            if self._values[engine]:
                painter.setPen(QPen(self.COLORS[engine], t))
                painter.drawArc(rect, 90 * 16, -int(360 * 16 * self._values[engine] / self._max))

        running = [value for value in self._values.values() if value is not None]
        if running and all(value >= self._max for value in running):
            pen_check = QPen(QColor(0, 180, 0), t)
            pen_check.setCapStyle(Qt.RoundCap)
            painter.setPen(pen_check)
            x, y, w, h = inner.x(), inner.y(), inner.width(), inner.height()
            painter.drawLine(x + w * 0.25, y + h * 0.5, x + w * 0.43, y + h * 0.7)
            painter.drawLine(x + w * 0.43, y + h * 0.7, x + w * 0.75, y + h * 0.3)
        elif running:
            font = painter.font()
            font.setPixelSize(max(int(inner.width() * 0.2), 10))
            painter.setFont(font)
            painter.setPen(self.palette().windowText().color())
            painter.drawText(inner, Qt.AlignCenter, f"{sum(running) / len(running) / 10:.1f}%")
        painter.end()

class FeedPicker(QDialog):
    """
    A checklist of every ClamAV and YARA feed, for scanning with just some of them
    """

    def __init__(self, checked, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Choose feeds")
        self.list = QListWidget()
        for engine, feeds in (("clam", clam_feeds()), ("yara", yara_utils.list_feeds())):
            for index, feed in feeds.items():
                item = QListWidgetItem(f"{index} ({ENGINES[engine]}, {feed.get('level', 'quick')})")
                item.setData(Qt.UserRole, index)
                item.setCheckState(Qt.Checked if checked is None or index in checked else Qt.Unchecked)
                self.list.addItem(item)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.list)
        layout.addWidget(buttons)

    def checked(self):
        return [self.list.item(i).data(Qt.UserRole) for i in range(self.list.count()) if self.list.item(i).checkState() == Qt.Checked]

class ClamPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Menoa - Malware Scanning")
        self._scans = {}  # engine: (Scanner, QThread) of the latest scan
        self._running = 0
        self._statuses = {}
        self._chosen_feeds = None  # From "Choose feeds...", None for all of them
        self._setup_ui()
        self._load_db_info()

        # Paths for quick scan
        self._quick_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents")
        ]

    def _setup_ui(self):
        # Progress rings
        self.circular = CircularProgress(thickness=12)
        legend = QLabel(" ".join(f'<span style="color: {CircularProgress.COLORS[e].name()};">&#9679;</span> {ENGINES[e]} ({ring})'
                                 for e, ring in (("clam", "inner"), ("yara", "outer"))))
        top = QGroupBox("Malware Scanning")
        tl = QVBoxLayout()
        tl.addWidget(self.circular, alignment=Qt.AlignCenter)
        tl.addWidget(legend, alignment=Qt.AlignCenter)
        top.setLayout(tl)

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

        # Which feeds scans use, and the buttons, the first row scans with both engines
        self.feed_choice = QComboBox()
        self.feed_choice.addItems(["All feeds"] + [f"{level.title()} level feeds" for level in FEED_LEVELS] + ["Choose feeds..."])
        self.feed_choice.activated.connect(self._feed_choice_changed)
        self._last_choice = 0
        self.feeds_used = QLabel()
        self.feeds_used.setWordWrap(True)
        fl = QHBoxLayout()
        fl.addWidget(QLabel("Scan with:"))
        fl.addWidget(self.feed_choice)
        fl.addWidget(self.feeds_used, stretch=1)

        btns = QGroupBox()
        bl = QVBoxLayout()
        bl.addLayout(fl)
        rows = [
            [("Quick Scan", self.quick_scan), ("Scan Folder", self.scan_folder), ("Scan File", self.scan_file), ("Full Scan", self.full_scan)],
            [("ClamAV: Scan Folder", lambda: self.scan_folder(("clam",))), ("ClamAV: Scan File", lambda: self.scan_file(("clam",))),
             ("YARA: Scan Folder", lambda: self.scan_folder(("yara",))), ("YARA: Scan File", lambda: self.scan_file(("yara",)))],
        ]
        for row in rows:
            rl = QHBoxLayout()
            for text, handler in row:
                b = QPushButton(text)
                b.clicked.connect(lambda checked=False, handler=handler: handler())
                rl.addWidget(b)
            bl.addLayout(rl)
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
        self._show_feeds_used()

    def showEvent(self, event):
        # Feeds can be added or removed from the CLI while Menoa is open
        self._show_feeds_used()
        super().showEvent(event)

    def _feed_selection(self):
        # (feeds, level) for utils.feeds_by_engine() from the feed picker
        choice = self.feed_choice.currentIndex()
        if choice == len(FEED_LEVELS) + 1:
            return self._chosen_feeds or [], None
        return (), FEED_LEVELS[choice - 1] if choice else None

    def _feeds_used(self, engines):
        feeds, level = self._feed_selection()
        if feeds == []:  # Everything unticked in "Choose feeds...", an empty list would mean all of them
            return {}
        return {engine: names for engine, names in feeds_by_engine(engines, feeds, level).items() if names}

    def _show_feeds_used(self):
        try:
            used = self._feeds_used(("clam", "yara"))
            self.feeds_used.setText("\n".join(f"{ENGINES[e]}: {', '.join(names)}" for e, names in used.items()) or "No feeds selected")
        except Exception as e:  # A chosen feed was removed from the config
            self.feeds_used.setText(str(e))

    @Slot(int)
    def _feed_choice_changed(self, choice):
        if choice == len(FEED_LEVELS) + 1:
            picker = FeedPicker(self._chosen_feeds, self)
            if picker.exec() != QDialog.Accepted:
                self.feed_choice.setCurrentIndex(self._last_choice)
                return
            self._chosen_feeds = picker.checked()
        self._last_choice = choice
        self._show_feeds_used()

    @Slot()
    def update_databases(self):
        # YARA first, it returns its failures instead of raising, so a failed ClamAV update doesn't skip it
        failures = run_with_progress(lambda progress: yara_utils.update_all_feeds() + (update_all_feeds(progress) or []), "Updating malware signatures...")
        if failures:
            QMessageBox.warning(self, "Menoa", "Updating the malware signatures failed:\n\n" + "\n".join(failures))
        self._load_db_info()

    def _start_scan(self, paths, engines=None):
        """
        Starts a Scanner per engine on its own thread. Without engines, both, or just ClamAV while there are no YARA feeds
        """
        # The threads, not _running: a thread is still stopping for a moment after its worker says it's finished
        if any(thread.isRunning() for _, thread in self._scans.values()):
            return
        if isinstance(paths, str):
            paths = [paths]
        both = engines is None
        try:
            used = self._feeds_used(("clam", "yara") if both else engines)
        except Exception as e:
            self.log_box.append(f"SCAN NOT STARTED: {e}")
            return
        if not used:
            self.log_box.append(f"SCAN NOT STARTED: no {' or '.join(ENGINES[e] for e in (engines or ENGINES))} feeds selected")
            return
        if both and len(used) == 1:
            self.log_box.append(f"No {ENGINES[({'clam', 'yara'} - set(used)).pop()]} feeds selected, scanning with {ENGINES[next(iter(used))]} only")
        engines = tuple(used)
        feeds, level = self._feed_selection()

        self.log_box.append(f"Starting {' and '.join(ENGINES[e] for e in engines)} scan: {', '.join(paths)}")
        for engine in engines:
            self.log_box.append(f"{ENGINES[engine]} feeds: {', '.join(used[engine])}")
        self._scans, self._statuses, self._running = {}, {}, len(engines)
        self.circular.start(engines)

        for engine in engines:
            worker = Scanner(engine, used[engine] if feeds else None, level)
            worker.set_scan_path(*paths)
            thread = QThread()
            worker.moveToThread(thread)
            thread.started.connect(worker.scan)

            # Bound methods of the page, so they run on the GUI thread
            worker.progress.connect(self._clam_progress if engine == "clam" else self._yara_progress)
            worker.status.connect(self._clam_status if engine == "clam" else self._yara_status)
            worker.log.connect(self.log_box.append)
            worker.finished.connect(thread.quit)
            worker.finished.connect(self._scan_finished)

            self._scans[engine] = (worker, thread)
            thread.start()

    @Slot(int)
    def _clam_progress(self, value):
        self.circular.setValue(value, "clam")

    @Slot(int)
    def _yara_progress(self, value):
        self.circular.setValue(value, "yara")

    @Slot(str)
    def _clam_status(self, text):
        self._show_status("clam", text)

    @Slot(str)
    def _yara_status(self, text):
        self._show_status("yara", text)

    def _show_status(self, engine, text):
        self._statuses[engine] = text
        if len(self._scans) == 1:
            self.status1.setText(text)
        else:
            self.status1.setText("\n".join(f"{ENGINES[e]}: {self._statuses[e]}" for e in self._scans if e in self._statuses))

    @Slot()
    def _scan_finished(self):
        self._running -= 1
        if not self._running:
            self._load_db_info()  # Also updates "Last scan"

    @Slot()
    def quick_scan(self):
        paths = [path for path in self._quick_paths if os.path.exists(path)]
        if not paths:
            self.log_box.append("Nothing to quick scan: ~/Downloads and ~/Documents don't exist")
            return
        self._start_scan(paths)

    @Slot()
    def scan_folder(self, engines=None):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self._start_scan(folder, engines)

    @Slot()
    def scan_file(self, engines=None):
        file, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if file:
            self._start_scan(file, engines)

    @Slot()
    def full_scan(self):
        self._start_scan("/")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ClamPage()
    win.resize(600, 600)
    win.show()
    sys.exit(app.exec())
