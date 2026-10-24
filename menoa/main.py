import time

BIG_TIME=time.time()

def log(t, BIG_TIME):
    print(t, time.time()-BIG_TIME)
    BIG_TIME=time.time()
    return BIG_TIME

import sys
from PySide6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, Signal, QObject, QThread, QEventLoop
from PySide6.QtWidgets import QApplication, QWidget, QListWidget, QListWidgetItem, QHBoxLayout, QStackedWidget, QLabel, QVBoxLayout, QGridLayout, QFrame, QSizePolicy, QScrollArea, QToolButton, QDialog, QDialogButtonBox, QPushButton, QTextEdit, QProgressDialog, QMessageBox
from PySide6.QtGui import QDesktopServices, QCursor, QFont, QLinearGradient, QColor, QBrush, QIcon, QPalette
from PySide6.QtCore import QUrl, QEvent
import importlib.resources as pkg_resources
from pathlib import Path

BIG_TIME = log(1, BIG_TIME)

from menoa.pages.network_page import NetworkPage
BIG_TIME = log(1.1, BIG_TIME)

from menoa.pages.clam_page import ClamPage
BIG_TIME = log(1.2, BIG_TIME)

from menoa.pages.attestation_page import AttestationPage
BIG_TIME = log(1.3, BIG_TIME)

from menoa.pages.process_page import ProcessPage
BIG_TIME = log(1.4, BIG_TIME)

from menoa.pages.process_page import PredictionEngine
BIG_TIME = log(1.45, BIG_TIME)


from menoa.pages.script_page import ScriptPage
from menoa.pages.progress_dialog import run_with_progress
BIG_TIME = log(1.5, BIG_TIME)

from menoa.utils.utils import get_enabled_tools
from menoa.utils.clam_utils import database_freshness, get_last_time_scanned

BIG_TIME = log(2, BIG_TIME)

# Fixed width for dashboard cards (pixels). Adjust this value if you change the
# application minimum width or the number of columns in the grid.
CARD_FIXED_WIDTH = 360


class LearnMoreDialog(QDialog):
    """Simple modal dialog that shows a title and a read-only, scrollable description."""
    def __init__(self, title: str, content: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"About {title}")
        self.setModal(True)

        layout = QVBoxLayout(self)
        title_label = QLabel(f"<b>{title}</b>")
        title_label.setObjectName("dashboard_label")
        layout.addWidget(title_label)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(content or "")
        text.setMinimumSize(480, 260)
        layout.addWidget(text)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        # Close button mapping
        close_button = buttons.button(QDialogButtonBox.Close)
        if close_button:
            close_button.setText("Close")
        layout.addWidget(buttons)


class DashboardCard(QFrame):
    cardClicked = Signal()
    def __init__(self, title, short_desc, long_desc, link, section):
        super().__init__()
        self.section = section  # The tool's section in config.toml, None for tools without a background switch
        # store fields for the learn dialog
        self.link = link
        self.title = title
        # keep both short (dashboard) and long (popup) descriptions
        self.short_desc = short_desc
        self.long_desc = long_desc
        # Make each card the same fixed width so the grid looks uniform
        self.setFixedWidth(CARD_FIXED_WIDTH)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setLineWidth(1)
        self.setObjectName("dashboardCard")
        self.setMinimumHeight(180)
        self.setCursor(QCursor(Qt.PointingHandCursor))

        self.header = QWidget()
        self.header.setObjectName("cardHeader")
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(15, 8, 15, 8)

        # Title with status indicator
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        title_label = QLabel(f"<b>{title}</b>")
        title_label.setObjectName("dashboard_label")

        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)

        title_layout.addWidget(title_label)
        title_layout.addWidget(self.status_label)

        header_layout.addLayout(title_layout)
        header_layout.addStretch()

        # Content area
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(15, 10, 15, 15)
        content_layout.setSpacing(8)

        # show the short description on the dashboard card
        desc_label = QLabel(short_desc)
        desc_label.setWordWrap(True)
        desc_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        # Learn more button
        learn_btn = QToolButton()
        learn_btn.setText("Learn more →")
        learn_btn.setObjectName("learnButton")
        learn_btn.setCursor(QCursor(Qt.PointingHandCursor))
        learn_btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        learn_btn.setIconSize(QSize(16, 16))
        learn_btn.setIcon(QIcon.fromTheme("go-next"))
        # Open a native dialog with information instead of launching the browser
        learn_btn.clicked.connect(self.open_learn_dialog)

        content_layout.addWidget(desc_label)
        content_layout.addStretch()
        content_layout.addWidget(learn_btn, 0, Qt.AlignLeft)

        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.header)
        main_layout.addWidget(content)

    def set_status(self, enabled_tools):
        if self.section is None:
            return
        enabled = self.section in enabled_tools
        self.status_label.setText("Enabled" if enabled else "Disabled")
        self.status_label.setStyleSheet(f"color: {'#4CAF50' if enabled else '#F44336'};")

    def mousePressEvent(self, event):
        """Handle mouse click events for the entire card"""
        if event.button() == Qt.LeftButton:
            self.cardClicked.emit() # Emit signal when card is clicked
            event.accept()
        else:
            super().mousePressEvent(event)

    def open_learn_dialog(self):
        """Show a native modal dialog with the card's long description."""
        dlg = LearnMoreDialog(self.title, self.long_desc, parent=self)
        dlg.exec()

class DashboardPage(QWidget):
    pageRequested = Signal(int) # Page navigation signal
    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 15, 20, 20)
        main_layout.setSpacing(25)

        # Header
        header = QWidget()
        header_layout = QHBoxLayout(header)

        title = QLabel("Menoa Dashboard")
        title.setObjectName("dashboard_title")

        header_layout.addWidget(title)
        header_layout.addSpacing(20)

        main_layout.addWidget(header)

        # Stats bar
        stats_bar = QWidget()
        stats_bar.setObjectName("statsBar")
        stats_layout = QHBoxLayout(stats_bar)
        stats_layout.setContentsMargins(15, 12, 15, 12)

        # Values are filled in by refresh()
        self.stat_values = {}
        for label in ("Active Tools", "Signatures", "Last Scan"):
            stat = QWidget()
            stat_layout = QVBoxLayout(stat)

            lbl = QLabel(label)
            lbl.setObjectName("dashboard_stats_label")
            lbl.setStyleSheet("color: #777777;")

            val = QLabel()
            val.setObjectName("dashboard_stats_value")
            self.stat_values[label] = val

            stat_layout.addWidget(lbl)
            stat_layout.addWidget(val)
            stats_layout.addWidget(stat)
            stats_layout.addSpacing(30)

        main_layout.addWidget(stats_bar)

        # Tools grid
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        grid_container = QWidget()
        grid_layout = QGridLayout(grid_container)
        grid_layout.setContentsMargins(0, 0, 0, 20)
        grid_layout.setHorizontalSpacing(20)
        grid_layout.setVerticalSpacing(20)
        grid_layout.setAlignment(Qt.AlignTop)

        # Tools grid setup
        scroll_area = QScrollArea()

        tools = [
            (
                "ClamAV Scanner",
                "Malware scanner",
                "A GUI front end for scanning files and directories for malware with ClamAV. Use it to scan files for malware.",
                "https://github.com/ThisIsNotANamepng/Menoa/wiki/Tools#clam",
                1, "clamav",
            ),
            (
                "Endpoint Scanner",
                "Endpoint connection scanning",
                "Compares active connections against known malicious endpoints.",
                "https://github.com/ThisIsNotANamepng/Menoa/wiki/Tools#network-scanner",
                2, "network",
            ),
            (
                "Process Scanner (beta)",
                "Process classifier",
                "Gathers information about current processes and classifies them as benign or malicious. Still in beta.",
                "https://github.com/ThisIsNotANamepng/Menoa/wiki/Tools#process",
                3, "process",
            ),
            (
                "Attestation (beta)",
                "Binary attestation",
                "Compares the hashes of local binaries in /bin against a list of correct hashes for Linux binaries.",
                "https://github.com/ThisIsNotANamepng/Menoa/wiki/Tools#attestation",
                4, "attestation",
            ),
            (
                "Command Predictor (beta)",
                "Bash parser and predictor",
                "Parses a given bash script and predicts in simple language what the outcome will be. Originally meant for install.sh scripts.",
                "https://github.com/ThisIsNotANamepng/Menoa/wiki/Tools#command",
                5, None,  # Only runs on demand, there's nothing to enable
            ),
        ]

        # Create cards, each (title, short description, long description, link, page index, config section)
        self.cards = []
        for i, (title, short_desc, long_desc, link, page, section) in enumerate(tools):
            row = i // 2
            col = i % 2

            card = DashboardCard(title, short_desc, long_desc, link, section)
            # When card clicked go to page
            card.cardClicked.connect(lambda idx=page: self.pageRequested.emit(idx))
            grid_layout.addWidget(card, row, col)
            self.cards.append(card)

        scroll_area.setWidget(grid_container)
        main_layout.addWidget(scroll_area, 1)

        self.setLayout(main_layout)
        self.refresh()

    def showEvent(self, event):
        # Settings can change from the CLI or other pages while Menoa is open
        self.refresh()
        super().showEvent(event)

    def refresh(self):
        enabled_tools = get_enabled_tools()
        for card in self.cards:
            card.set_status(enabled_tools)

        state, text = database_freshness()
        values = {
            "Active Tools": (str(len(enabled_tools)), "#00b57b"),
            "Signatures": (text.removeprefix("Malware signatures are ") if state != "missing" else "Not downloaded",
                           {"fresh": "#4CAF50", "outdated": "#FF9800"}.get(state, "#F44336")),
            "Last Scan": (get_last_time_scanned(), "#00b57b"),
        }
        for label, (value, color) in values.items():
            self.stat_values[label].setText(value)
            self.stat_values[label].setStyleSheet(f"color: {color};")

class MainWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Menoa")
        self.setWindowIcon(QIcon(str(Path.home()) + "/notification_icon.png"))

        #self.setMinimumSize(1000, 700)

        # Create menu
        self.menu_widget = QListWidget()
        self.menu_widget.setFixedWidth(220)
        self.menu_widget.setObjectName("menuWidget")
        self.menu_widget.setSpacing(4)

        menu_items = ["Dashboard", "Clam", "Network", "Process", "Attestation", "Command"]

        for title in menu_items:
            item = QListWidgetItem(title)
            item.setTextAlignment(Qt.AlignCenter)
            item.setSizeHint(QSize(200, 50))

            self.menu_widget.addItem(item)

        engine = PredictionEngine()
        self.dashboard_page = DashboardPage()
        self.stack = QStackedWidget()
        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(ClamPage())
        self.stack.addWidget(NetworkPage())
        self.stack.addWidget(ProcessPage(engine))
        self.stack.addWidget(AttestationPage())
        self.stack.addWidget(ScriptPage())

        self.menu_widget.currentRowChanged.connect(self.display_page)
        self.dashboard_page.pageRequested.connect(self.display_page)

        # Main layout
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.menu_widget, 1)
        layout.addWidget(self.stack, 3)

        self.setLayout(layout)
        self.menu_widget.setCurrentRow(0)

    def display_page(self, index):
        self.menu_widget.setCurrentRow(index)
        self.stack.setCurrentIndex(index)

def first_time_setup():
    """
    Creates the default config and downloads feeds with a progress bar, then reports any steps that failed
    """
    from menoa.utils.utils import initialize
    failures = run_with_progress(initialize, "Setting up Menoa...", "Menoa setup")

    if failures:
        QMessageBox.warning(None, "Menoa setup",
            "Some setup steps failed, Menoa will open without them:\n\n" + "\n".join(failures) + "\n\nRun `menoa init` to retry.")

def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("/home/jack/code/Menoa/menoa/notification_icon.png"))

    # Dark mode and light mode
    if QApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark:
        with pkg_resources.open_text("menoa", "dark_style.qss") as f:
            app.setStyleSheet(f.read())
    else:
        with pkg_resources.open_text("menoa", "light_style.qss") as f:
            app.setStyleSheet(f.read())

    if not (Path.home() / ".menoa" / "config.toml").exists():
        first_time_setup()

    w = MainWidget()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
