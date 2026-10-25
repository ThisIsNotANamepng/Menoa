"""
Checks the Settings page reads and writes the same settings as the CLI. Run with `python tests/test_settings_page.py` (or pytest)
"""

import os, sys, tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
(Path.home() / ".menoa").mkdir()

import tomli
from click.testing import CliRunner
from menoa.cli import cli

CONFIG = Path.home() / ".menoa" / "config.toml"


def status_rows():
    # `menoa status` as {tool: [background, scan every, feeds update every]}
    output = CliRunner().invoke(cli, ["status"]).output
    return {line.split("│")[1].strip(): [cell.strip() for cell in line.split("│")[2:5]] for line in output.splitlines() if line.count("│") == 5}


def test_settings_match_the_cli():
    from PySide6.QtWidgets import QApplication, QMessageBox
    from menoa.pages.settings_page import SettingsPage
    import menoa.utils.process_utils as process_utils
    app = QApplication.instance() or QApplication([])

    # No [yara] section, like configs from before YARA was its own tool
    CONFIG.write_text("".join(f"[{tool}]\nscan_delay = 600\nfeed_update_delay = 21600\nenabled = true\nthreshold = 0.7\n" for tool in ("clamav", "network", "process", "attestation")))
    page = SettingsPage()

    # Delays show in their largest whole unit
    shown = lambda field: (field.number.value(), field.unit.currentText())
    assert shown(page.scan_delays["clamav"]) == (10, "minutes") and shown(page.feed_delays["clamav"]) == (6, "hours")
    assert shown(page.feed_delays["yara"]) == (7, "days") and "process" not in page.feed_delays

    # Changes are saved where the CLI reads them
    page.switches["network"].setChecked(False)
    page.scan_delays["network"].unit.setCurrentText("seconds")
    page.scan_delays["network"].number.setValue(90)
    page.scan_delays["process"].number.setValue(3)  # 3 minutes
    page.feed_delays["yara"].number.setValue(1)  # 1 day
    assert status_rows() == {
        "Tool": ["Background", "Scan every", "Feeds update every"],
        "ClamAV": ["on", "10m", "6h"],
        "YARA": ["on", "10m", "1d"],
        "Network": ["off", "90s", "6h"],
        "Process": ["on", "3m", "-"],
        "Attestation": ["on", "10m", "-"],
    }, status_rows()

    # And changes from the CLI show up, without being written back
    CliRunner().invoke(cli, ["clam", "delay", "--update", "7200"])
    CliRunner().invoke(cli, ["attestation", "toggle", "--off"])
    before = CONFIG.read_text()
    page.refresh()
    assert shown(page.feed_delays["clamav"]) == (2, "hours") and not page.switches["attestation"].isChecked()
    assert CONFIG.read_text() == before

    # The process model, like `menoa process model`
    changed = []
    page.model_changed.connect(lambda: changed.append(True))
    page.model_source.setText(" https://example.org/model.pkl ")
    page.model_key.setText("KEY")
    with mock.patch.object(process_utils, "set_model") as set_model:
        page.set_model(page.model_source.text().strip(), page.model_key.text().strip())
        page.set_model(None, "")  # Menoa's model
    assert [c.args for c in set_model.call_args_list] == [("https://example.org/model.pkl", "KEY"), (None, "")] and len(changed) == 2

    with mock.patch.object(process_utils, "set_model", side_effect=Exception("bad signature")), mock.patch.object(QMessageBox, "warning") as warning:
        page.set_model("/models/own.pkl", "KEY")
    assert warning.call_args[0][2] == "Model not changed: bad signature", warning.call_args

    with mock.patch.object(process_utils, "set_model") as set_model, mock.patch.object(QMessageBox, "warning") as warning:
        page.set_model("", "")  # "Use this model" with nothing entered
    assert not set_model.called and warning.called

    with mock.patch.object(process_utils, "get_model_settings", lambda: {"model_url": "/models/own.pkl", "model_public_key": ""}):
        page.refresh()
    assert page.model_label.text() == "Using your own model, not checked: /models/own.pkl"


if __name__ == "__main__":
    test_settings_match_the_cli()
    print("All settings page checks passed")
