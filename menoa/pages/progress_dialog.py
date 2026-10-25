"""
A progress bar dialog for slow work like downloads, with the work run off the GUI thread
"""

from typing import Callable, List

from PySide6.QtCore import Qt, Signal, QObject, QThread, QEventLoop
from PySide6.QtWidgets import QProgressDialog

class ProgressWorker(QObject):
    """
    Runs task(progress) off the GUI thread so the progress dialog stays responsive. The task returns a list of failures or raises
    """
    progress = Signal(str, int, int)
    finished = Signal(list)

    def __init__(self, task: Callable[[Callable[[str, int, int], None]], List[str]]) -> None:
        super().__init__()
        self.task = task

    def run(self) -> None:
        """
        Runs the task and emits finished with its failures, an exception counts as one failure
        """
        try:
            failures = self.task(lambda text, done, total: self.progress.emit(text, done, total))
        except Exception as e:
            failures = [str(e)]
        self.finished.emit(failures)

class ProgressDialog(QProgressDialog):
    """
    Progress bar for downloads. Its slots run on the GUI thread, since the dialog lives there
    """
    def __init__(self, label: str, title: str) -> None:
        super().__init__(label, None, 0, 0)
        self.setWindowTitle(title)
        self.setCancelButton(None)
        self.setMinimumDuration(0)
        self.setMinimumWidth(420)
        self.setWindowModality(Qt.ApplicationModal)  # No scans while their databases are being replaced
        # Without these the dialog hides itself whenever one file finishes
        self.setAutoClose(False)
        self.setAutoReset(False)
        self.failures = []

    def on_progress(self, text: str, done: int, total: int) -> None:
        """
        Shows how far the work is, a busy bar when total is 0 (unknown size)
        """
        if total:
            self.setRange(0, total)
            self.setValue(done)
            self.setLabelText(f"{text}\n{done / 1e6:.1f} of {total / 1e6:.1f} MB")
        else:
            self.setRange(0, 0)  # Unknown size, show a busy bar
            self.setLabelText(text)

    def on_finished(self, failures: List[str]) -> None:
        """
        Keeps the task's failures for run_with_progress() to return
        """
        self.failures = failures

def run_with_progress(task: Callable[[Callable[[str, int, int], None]], List[str]], label: str, title: str = "Menoa") -> List[str]:
    """
    Runs task(progress) with a progress bar and returns its failures, progress(text, done_bytes, total_bytes) updates the bar
    """
    dialog = ProgressDialog(label, title)
    thread = QThread()
    worker = ProgressWorker(task)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.progress.connect(dialog.on_progress)
    worker.finished.connect(dialog.on_finished)

    # Wait in a local event loop, closing the dialog early just hides it while the task finishes
    loop = QEventLoop()
    worker.finished.connect(loop.quit)
    dialog.show()
    thread.start()
    loop.exec()
    thread.quit()
    thread.wait()
    dialog.close()
    return dialog.failures
