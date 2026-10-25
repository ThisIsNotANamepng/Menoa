"""
The Settings page: each tool's background switch and delays, and which process model to use
The same settings as the CLI's `<tool> toggle`, `<tool> delay` and `process model`, both read and write config.toml
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox, QLabel, QCheckBox, QSpinBox, QComboBox,
                               QLineEdit, QPushButton, QMessageBox, QScrollArea, QFrame)

import menoa.utils.attestation_utils as attestation_utils
import menoa.utils.clam_utils as clam_utils
import menoa.utils.network_utils as network_utils
import menoa.utils.process_utils as process_utils
import menoa.utils.yara_utils as yara_utils
from menoa.utils.utils import get_enabled_tools
from menoa.pages.progress_dialog import run_with_progress
from menoa import theme

# (name, config section, utils module, whether it has feeds to update). The process model ships with Menoa and attestation has no feed
TOOLS = (("ClamAV", "clamav", clam_utils, True), ("YARA", "yara", yara_utils, True), ("Network", "network", network_utils, True),
         ("Process", "process", process_utils, False), ("Attestation", "attestation", attestation_utils, False))
UNITS = (("seconds", 1), ("minutes", 60), ("hours", 3600), ("days", 86400))

class DelayField(QWidget):
    """
    A delay as a number and a unit, like 10 minutes. Emits changed with the delay in seconds
    """
    changed = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self.number = QSpinBox()
        self.number.setRange(0, 1_000_000)
        self.unit = QComboBox()
        self.unit.addItems([name for name, _ in UNITS])
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.number)
        layout.addWidget(self.unit)
        self.number.valueChanged.connect(self._emit)
        self.unit.currentIndexChanged.connect(self._emit)

    def seconds(self) -> int:
        """
        Returns the delay in seconds
        """
        return self.number.value() * UNITS[self.unit.currentIndex()][1]

    def set_seconds(self, seconds: float) -> None:
        """
        Shows a delay in its largest whole unit, like 21600 as 6 hours, without emitting changed
        """
        seconds = int(seconds)
        index = 0
        for i, (_, size) in enumerate(UNITS):
            if seconds and seconds % size == 0:
                index = i
        self.blockSignals(True)
        self.unit.setCurrentIndex(index)
        self.number.setValue(seconds // UNITS[index][1])
        self.blockSignals(False)

    def _emit(self) -> None:
        """
        Emits changed with the new delay
        """
        self.changed.emit(self.seconds())

class SettingsPage(QWidget):
    """
    A section per tool with its background switch and delays, and the process model choice
    """
    model_changed = Signal()  # So the Process page loads the new model

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Menoa - Settings")
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        note = QLabel("Menoa has no background clock yet, so nothing runs in the background: these settings take effect once it does. "
                      "Until then, scan from the other pages")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {theme.COLORS['warning']};")
        layout.addWidget(note)

        self.switches, self.scan_delays, self.feed_delays = {}, {}, {}
        for name, section, module, has_feeds in TOOLS:
            box = QGroupBox(name)
            grid = QGridLayout(box)
            switch = QCheckBox("Run in the background")
            switch.toggled.connect(lambda on, module=module: module.toggle(on))
            grid.addWidget(switch, 0, 0, 1, 2)
            self.switches[section] = switch

            self.scan_delays[section] = DelayField()
            self.scan_delays[section].changed.connect(module.set_scanning_delay)
            grid.addWidget(QLabel("Scan every"), 1, 0, Qt.AlignLeft)
            grid.addWidget(self.scan_delays[section], 1, 1)
            if has_feeds:
                self.feed_delays[section] = DelayField()
                self.feed_delays[section].changed.connect(module.set_feed_update_delay)
                grid.addWidget(QLabel("Update feeds every"), 2, 0, Qt.AlignLeft)
                grid.addWidget(self.feed_delays[section], 2, 1)
            grid.setColumnStretch(2, 1)
            grid.setColumnMinimumWidth(0, 140)  # Lines the fields up across the sections
            layout.addWidget(box)

        layout.addWidget(self._model_box())
        layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(content)
        QVBoxLayout(self).addWidget(scroll)
        self.refresh()

    def _model_box(self) -> QGroupBox:
        """
        Builds the process model section: the current model, and a way to use your own or go back to Menoa's
        """
        box = QGroupBox("Process model")
        layout = QVBoxLayout(box)
        self.model_label = QLabel()
        self.model_source = QLineEdit()
        self.model_source.setPlaceholderText("URL or path of your own model")
        self.model_key = QLineEdit()
        self.model_key.setPlaceholderText("Public key it's signed with (optional, the signature is the model's URL or path + .sig)")
        warning = QLabel("Without a public key your own model isn't checked, only use models you trust: loading one runs code from it")
        warning.setWordWrap(True)
        warning.setStyleSheet(f"color: {theme.COLORS['warning']};")
        use_own = QPushButton("Use this model")
        use_own.clicked.connect(lambda: self.set_model(self.model_source.text().strip(), self.model_key.text().strip()))
        use_menoa = QPushButton("Use Menoa's model")
        use_menoa.clicked.connect(lambda: self.set_model(None, ""))
        buttons = QHBoxLayout()
        buttons.addWidget(use_own)
        buttons.addWidget(use_menoa)
        for widget in (self.model_label, self.model_source, self.model_key, warning):
            layout.addWidget(widget)
        layout.addLayout(buttons)
        return box

    def showEvent(self, event: QShowEvent) -> None:
        """
        Reloads the settings, they can change from the CLI while Menoa is open
        """
        self.refresh()
        super().showEvent(event)

    def refresh(self) -> None:
        """
        Shows the current settings from config.toml
        """
        enabled = get_enabled_tools()
        for name, section, module, has_feeds in TOOLS:
            self.switches[section].blockSignals(True)  # Showing a setting isn't changing it
            self.switches[section].setChecked(section in enabled)
            self.switches[section].blockSignals(False)
            delays = module.get_delay() if has_feeds else {"scan_delay": module.get_scanning_delay()}
            self.scan_delays[section].set_seconds(delays["scan_delay"])
            if has_feeds:
                self.feed_delays[section].set_seconds(delays["feed_update_delay"])

        settings = process_utils.get_model_settings()
        if process_utils.is_official_model(settings):
            self.model_label.setText("Using Menoa's built-in model")
        else:
            checked = "not checked" if process_utils.is_unsigned_model(settings) else "signed with your public key"
            self.model_label.setText(f"Using your own model, {checked}: {settings['model_url']}")

    def set_model(self, source: str, public_key: str) -> None:
        """
        Switches to the model at source, or Menoa's with none, like `menoa process model`. The model is only changed if it installs and passes its checks
        """
        if source == "":
            QMessageBox.warning(self, "Menoa", "Enter the URL or path of your model first")
            return
        failures = run_with_progress(lambda progress: process_utils.set_model(source, public_key) or [], "Installing the process model...")
        if failures:
            QMessageBox.warning(self, "Menoa", f"Model not changed: {failures[0]}")
        self.refresh()
        self.model_changed.emit()
