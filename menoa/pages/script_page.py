from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox, QDialog, QLineEdit, QDialogButtonBox
from PySide6.QtCore import QTimer, Qt

from utils.script_utils import parse_script, predict_actions, load_remote_script

class TemplateDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Menoa - Bash Parsing")
        self.resize(300, 100)

        # Create input field
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter template name...")

        # Create buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

        # Layout setup
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Template Name:"))
        layout.addWidget(self.input_field)
        layout.addWidget(self.button_box)

        self.setLayout(layout)

    def get_template_name(self):
        return self.input_field.text()

class ScriptPage(QWidget):
    def __init__(self):
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
        self.load_template_button = QPushButton("Remote URL")
        self.load_template_button.clicked.connect(self.show_template_dialog)

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.analyze_button)
        controls_layout.addWidget(self.load_template_button)
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

    def schedule_analysis(self):
        # Debounce analysis to avoid running on every keystroke
        self.analysis_timer.start(500)  # wait 500ms after last change

    def show_template_dialog(self):
        """Show template loading dialog with text input"""
        dialog = TemplateDialog(self)
        if dialog.exec() == QDialog.Accepted:
            template_name = dialog.get_template_name()
            self.load_template(template_name)

    def load_template(self, template_name):
        """Load template using user-provided name"""
        template = load_remote_script(template_name)
        self.script_input.setPlainText(template)

    def run_analysis(self):
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
