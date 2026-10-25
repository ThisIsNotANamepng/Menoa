"""
The Command page: predicts what a bash script would do, typed in or loaded from a URL
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox, QInputDialog
from PySide6.QtCore import QTimer

from menoa.utils.script_utils import parse_script, predict_actions, load_remote_script
from menoa.pages.progress_dialog import run_with_progress
from typing import Callable, List

class ScriptPage(QWidget):
    """
    A script box and buttons on the left, the predicted actions on the right, updated as you type
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Menoa - Bash Parsing")

        # --- Input Script Box ---
        self.input_group = QGroupBox("Bash Script Input")
        self.script_input = QTextEdit()
        self.script_input.setPlaceholderText("Paste or write your bash script here...")
        self.script_input.textChanged.connect(self.schedule_analysis)

        input_layout = QVBoxLayout()
        input_layout.addWidget(self.script_input)
        self.input_group.setLayout(input_layout)

        # --- Controls Box ---
        self.controls_group = QGroupBox("Controls")
        self.analyze_button = QPushButton("Analyze Now")
        self.analyze_button.clicked.connect(self.run_analysis)
        self.load_url_button = QPushButton("Load from URL")
        self.load_url_button.clicked.connect(self.show_url_dialog)

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.analyze_button)
        controls_layout.addWidget(self.load_url_button)
        self.controls_group.setLayout(controls_layout)

        # --- Prediction Output Box ---
        self.output_group = QGroupBox("Predicted Actions")
        self.output_view = QTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setLineWrapMode(QTextEdit.WidgetWidth)

        output_layout = QVBoxLayout()
        output_layout.addWidget(self.output_view)
        self.output_group.setLayout(output_layout)

        # --- Timer for Debounced Analysis ---
        self.analysis_timer = QTimer(self)
        self.analysis_timer.setSingleShot(True)
        self.analysis_timer.timeout.connect(self.run_analysis)

        # --- Layout ---
        left_layout = QVBoxLayout()
        left_layout.addWidget(self.input_group)
        left_layout.addWidget(self.controls_group)

        main_layout = QHBoxLayout()
        main_layout.addLayout(left_layout, 1)
        main_layout.addWidget(self.output_group, 2)

        self.setLayout(main_layout)

    def schedule_analysis(self) -> None:
        """
        Analyzes the script once typing stops, instead of on every keystroke
        """
        self.analysis_timer.start(500)  # wait 500ms after last change

    def show_url_dialog(self) -> None:
        """
        Asks for a script URL and loads it, for checking an install.sh before running it
        """
        url, ok = QInputDialog.getText(self, "Menoa - Load Script", "Script URL (like https://example.com/install.sh):")
        if ok and url.strip():
            self.load_url(url.strip())

    def load_url(self, url: str) -> None:
        """
        Downloads the script at url off the GUI thread, then analyzes it. A failed download leaves the script box as it was
        """
        script = []
        def download(progress: Callable[[str, int, int], None]) -> List[str]:
            script.append(load_remote_script(url))
            return []  # No failures, a failed download raises
        failures = run_with_progress(download, f"Downloading {url}...")
        if failures:
            self.output_view.setPlainText(f"Couldn't download {url}: {failures[0]}")
            return
        self.script_input.setPlainText(script[0])
        self.analysis_timer.stop()  # Analyzed now instead of after the typing delay, with where it came from on top
        self.run_analysis()
        self.output_view.setPlainText(f"Script from {url}\n\n{self.output_view.toPlainText()}")

    def run_analysis(self) -> None:
        """
        Shows the predicted actions of the script in the box
        """
        script_text = self.script_input.toPlainText()
        if not script_text.strip():
            self.output_view.setPlainText("No script provided.")
            return

        try:
            # Parse the script into AST or action list
            parsed = parse_script(script_text)
            # Predict actions and potential side-effects
            predictions = predict_actions(parsed)
            # Display results
            self.output_view.setPlainText("\n".join(predictions))
        except Exception as e:
            self.output_view.setPlainText(f"Error during analysis: {e}")
