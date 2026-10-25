"""
The GUI (menoa-gui): the main window with the left column, the dashboard, and one page per tool
"""

import sys
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import Qt, QSize, Signal
from PySide6.QtWidgets import QApplication, QWidget, QListWidget, QListWidgetItem, QHBoxLayout, QStackedWidget, QLabel, QVBoxLayout, QGridLayout, QFrame, QSizePolicy, QScrollArea, QToolButton, QDialog, QDialogButtonBox, QTextEdit, QMessageBox
from PySide6.QtGui import QCursor, QIcon, QMouseEvent, QPixmap, QShowEvent

from menoa import theme
from menoa.pages.network_page import NetworkPage
from menoa.pages.clam_page import ClamPage
from menoa.pages.attestation_page import AttestationPage
from menoa.pages.process_page import ProcessPage, PredictionEngine
from menoa.pages.script_page import ScriptPage
from menoa.pages.progress_dialog import run_with_progress
from menoa.utils.utils import get_enabled_tools, ICON_PATH
from menoa.utils.clam_utils import database_freshness, get_last_time_scanned


class LearnMoreDialog(QDialog):
    """
    A modal dialog with a title and a read-only, scrollable description
    """

    def __init__(self, title: str, content: str, parent: Optional[QWidget] = None) -> None:
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
    """
    A tool's card on the dashboard: its name, whether it's enabled, a short description and a Learn more link. Clicking it opens the tool's page
    """
    cardClicked = Signal()

    def __init__(self, title: str, short_desc: str, long_desc: str, link: str, section: Optional[str]) -> None:
        super().__init__()
        self.section = section  # The tool's section in config.toml, None for tools without a background switch
        # store fields for the learn dialog
        self.link = link
        self.title = title
        # keep both short (dashboard) and long (popup) descriptions
        self.short_desc = short_desc
        self.long_desc = long_desc
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

        title_layout.addWidget(title_label)
        title_layout.addWidget(self.status_label, 0, Qt.AlignLeft)

        header_layout.addLayout(title_layout)
        header_layout.addStretch()

        # Content area
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(15, 10, 15, 15)
        content_layout.setSpacing(8)

        # show the short description on the dashboard card
        desc_label = QLabel(short_desc)
        desc_label.setObjectName("cardDescription")
        desc_label.setWordWrap(True)
        desc_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        # Learn more button
        learn_btn = QToolButton()
        learn_btn.setText("Learn more →")
        learn_btn.setObjectName("learnButton")
        learn_btn.setCursor(QCursor(Qt.PointingHandCursor))
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

    def set_status(self, enabled_tools: List[str]) -> None:
        """
        Shows Enabled or Disabled from get_enabled_tools(), nothing for tools without a background switch
        """
        if self.section is None:
            return
        enabled = self.section in enabled_tools
        self.status_label.setText("Enabled" if enabled else "Disabled")
        color = theme.COLORS["good" if enabled else "bad"]
        self.status_label.setStyleSheet(f"color: {color}; border: 1px solid {color}; border-radius: 9px; padding: 1px 8px; font-size: 12px;")

    def mousePressEvent(self, event: QMouseEvent) -> None:
        """
        Emits cardClicked when the card is left clicked anywhere
        """
        if event.button() == Qt.LeftButton:
            self.cardClicked.emit() # Emit signal when card is clicked
            event.accept()
        else:
            super().mousePressEvent(event)

    def open_learn_dialog(self) -> None:
        """
        Shows the card's long description in a dialog
        """
        dlg = LearnMoreDialog(self.title, self.long_desc, parent=self)
        dlg.exec()

class DashboardPage(QWidget):
    """
    The stats and a card per tool
    """
    pageRequested = Signal(int) # Page navigation signal

    def __init__(self) -> None:
        super().__init__()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 15, 20, 20)
        main_layout.setSpacing(25)

        # Header
        header = QWidget()
        header_layout = QHBoxLayout(header)

        title = QLabel("Dashboard")
        title.setObjectName("dashboard_title")

        header_layout.addWidget(title)
        header_layout.addSpacing(20)

        main_layout.addWidget(header)

        # Stats, a small card each
        stats_bar = QWidget()
        stats_layout = QHBoxLayout(stats_bar)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setSpacing(20)

        # Values are filled in by refresh()
        self.stat_values = {}
        for label in ("Active Tools", "Signatures", "Last Scan"):
            stat = QFrame()
            stat.setObjectName("statCard")
            stat_layout = QVBoxLayout(stat)
            stat_layout.setContentsMargins(15, 12, 15, 12)

            lbl = QLabel(label)
            lbl.setObjectName("dashboard_stats_label")

            val = QLabel()
            val.setObjectName("dashboard_stats_value")
            self.stat_values[label] = val

            stat_layout.addWidget(lbl)
            stat_layout.addWidget(val)
            stats_layout.addWidget(stat, 1)

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
        for col in (0, 1):  # Cards share the width
            grid_layout.setColumnStretch(col, 1)

        tools = [
            (
                "ClamAV Scanner",
                "Malware scanner",
                "A GUI front end for scanning files and directories for malware with ClamAV. Use it to scan files for malware.",
                "https://github.com/ThisIsNotANamepng/Menoa/wiki/Tools#clam",
                1, "clamav",
            ),
            (
                "YARA Scanner",
                "YARA rule scanner",
                "Scans files and directories with YARA rules using YARA-X, together with ClamAV or on its own. Add rule feeds with `menoa yara add`.",
                "https://github.com/ThisIsNotANamepng/Menoa/wiki/Tools#yara",
                1, "yara",
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

    def showEvent(self, event: QShowEvent) -> None:
        """
        Refreshes the stats and cards, settings can change from the CLI or other pages while Menoa is open
        """
        self.refresh()
        super().showEvent(event)

    def refresh(self) -> None:
        """
        Reloads which tools are enabled, the signature age and the last scan
        """
        enabled_tools = get_enabled_tools()
        for card in self.cards:
            card.set_status(enabled_tools)

        state, text = database_freshness()
        values = {
            "Active Tools": (str(len(enabled_tools)), theme.COLORS["accent_text"]),
            "Signatures": (text.removeprefix("Malware signatures are ") if state != "missing" else "Not downloaded", theme.freshness_color(state)),
            "Last Scan": (get_last_time_scanned(), theme.COLORS["accent_text"]),
        }
        for label, (value, color) in values.items():
            self.stat_values[label].setText(value)
            self.stat_values[label].setStyleSheet(f"color: {color};")

class MainWidget(QWidget):
    """
    The main window: the left column and the page it selects
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Menoa")

        # Create menu
        self.menu_widget = QListWidget()
        self.menu_widget.setObjectName("menuWidget")
        self.menu_widget.setSpacing(2)

        menu_items = ["Dashboard", "Malware Scanning", "Network", "Process", "Attestation", "Command"]

        for title in menu_items:
            item = QListWidgetItem(title)
            item.setSizeHint(QSize(200, 46))

            self.menu_widget.addItem(item)

        # Left column: the logo and name above the menu
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setAttribute(Qt.WA_StyledBackground)  # Otherwise a plain QWidget ignores its stylesheet background
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 20, 1, 10)  # 1px for its right border
        logo = QLabel()
        logo.setPixmap(QPixmap(str(ICON_PATH)).scaled(72, 72, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        name = QLabel("Menoa")
        name.setObjectName("sidebarName")
        sidebar_layout.addWidget(logo)
        sidebar_layout.addWidget(name)
        sidebar_layout.addSpacing(15)
        sidebar_layout.addWidget(self.menu_widget, 1)

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
        layout.addWidget(sidebar)
        layout.addWidget(self.stack, 1)

        self.setLayout(layout)
        self.menu_widget.setCurrentRow(0)

    def display_page(self, index: int) -> None:
        """
        Shows a page by its place in the left column
        """
        self.menu_widget.setCurrentRow(index)
        self.stack.setCurrentIndex(index)

def first_time_setup() -> None:
    """
    Creates the default config and downloads feeds with a progress bar, then reports any steps that failed
    """
    from menoa.utils.utils import initialize
    failures = run_with_progress(initialize, "Setting up Menoa...", "Menoa setup")

    if failures:
        QMessageBox.warning(None, "Menoa setup",
            "Some setup steps failed, Menoa will open without them:\n\n" + "\n".join(failures) + "\n\nRun `menoa init` to retry.")

def main() -> None:
    """
    Starts the GUI, setting Menoa up first if it's the first run
    """
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(ICON_PATH)))  # Every window uses it

    theme.apply(app)  # Dark or light, like the desktop

    if not (Path.home() / ".menoa" / "config.toml").exists():
        first_time_setup()

    w = MainWidget()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
