"""
Checks Menoa's icon and app menu entry work wherever Menoa is installed. Run with `python tests/test_desktop.py` (or pytest)
"""

import os, shutil, subprocess, sys, tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["HOME"] = tempfile.mkdtemp()

from menoa.utils import utils

DESKTOP = Path.home() / ".local" / "share" / "applications" / "menoa.desktop"


def install_folder():
    # A bin folder like a venv's or pipx's, with both console scripts next to each other
    folder = Path(tempfile.mkdtemp()) / "with space" / "bin"
    folder.mkdir(parents=True)
    for script in ("menoa", "menoa-gui"):
        (folder / script).write_text("#!/bin/sh\n")
    return folder


def test_no_paths_from_a_developer_machine():
    for source in (ROOT / "menoa").rglob("*.py"):
        assert "/home/jack" not in source.read_text(), source
    assert utils.ICON_PATH.is_file() and utils.ICON_PATH.parent == ROOT / "menoa"


def test_desktop_entry():
    first = install_folder()
    with mock.patch.object(sys, "argv", [str(first / "menoa"), "init"]):
        utils.initialize_desktop_file()

    entry = DESKTOP.read_text()
    assert f'Exec="{first}/menoa-gui"\n' in entry, entry
    assert f"Icon={Path.home()}/.menoa/app_icon.png\n" in entry, entry
    assert (Path.home() / ".menoa" / "app_icon.png").read_bytes() == utils.ICON_PATH.read_bytes()

    if shutil.which("desktop-file-validate"):
        result = subprocess.run(["desktop-file-validate", str(DESKTOP)], capture_output=True, text=True)
        assert result.returncode == 0 and not result.stdout.strip(), result.stdout

    # Reinstalled somewhere else, the next init follows it
    second = install_folder()
    with mock.patch.object(sys, "argv", [str(second / "menoa"), "init"]):
        utils.initialize_desktop_file()
    assert f'Exec="{second}/menoa-gui"\n' in DESKTOP.read_text()


if __name__ == "__main__":
    test_no_paths_from_a_developer_machine()
    test_desktop_entry()
    print("All desktop checks passed")
