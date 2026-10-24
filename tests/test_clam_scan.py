"""
Checks that clam scans never report a failed scan as clean. Run with `python tests/test_clam_scan.py` (or pytest)
Uses a fake clamscan that replays real clamscan output, so no signature database is needed
"""

import os, stat, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
(Path.home() / ".menoa" / "feeds" / "clam" / "standard").mkdir(parents=True)

FAKE_BIN = Path(tempfile.mkdtemp())
(FAKE_BIN / "clamscan").write_text('#!/bin/sh\ncat "$FAKE_CLAM_OUT"\nexit "$FAKE_CLAM_EXIT"\n')
(FAKE_BIN / "clamscan").chmod(stat.S_IRWXU)
os.environ["PATH"] = f"{FAKE_BIN}:{os.environ['PATH']}"

from click.testing import CliRunner
from menoa.utils import clam_utils
from menoa.cli import cli

SUMMARY = "\n----------- SCAN SUMMARY -----------\nKnown viruses: {viruses}\nEngine version: 1.4.4\nScanned files: 2\n"

GOOD = """/t/broken_link: Symbolic link
/t/locked.txt: Access denied
/t/empty.txt: Empty file
/t/eicar.com: Eicar-Test-Signature FOUND
/t/locked_dir: Can't open directory.
/t/sub/a.txt: OK
""" + SUMMARY.format(viruses=3628191)

BROKEN_DB = """LibClamAV Error: cli_loaddbdir: No supported database files found in /x
ERROR: Can't open file or directory
""" + SUMMARY.format(viruses=0)

CRASHED = "/t/sub/a.txt: OK\n"

CLEAN = "/t/sub/a.txt: OK\n/t/empty.txt: Empty file\n" + SUMMARY.format(viruses=10)


def fake(output, exit_code):
    f = Path(tempfile.mkstemp()[1])
    f.write_text(output)
    os.environ["FAKE_CLAM_OUT"] = str(f)
    os.environ["FAKE_CLAM_EXIT"] = str(exit_code)


def scan_all():
    return list(clam_utils.scan_path_streaming(tempfile.gettempdir()))


def test_good_scan_classification():
    fake(GOOD, 1)
    kinds = {f: clam_utils.result_kind(f, r) for f, r in scan_all()}
    assert kinds == {
        "/t/broken_link": "clean", "/t/locked.txt": "error", "/t/empty.txt": "clean",
        "/t/eicar.com": "infected", "/t/locked_dir": "error", "/t/sub/a.txt": "clean",
    }, kinds  # summary lines must not show up as files


def test_failed_scans_raise():
    for output, code, expected in [(BROKEN_DB, 2, "No malware signatures"), (CRASHED, 2, "before finishing")]:
        fake(output, code)
        try:
            scan_all()
            assert False, f"{expected} should have raised"
        except Exception as e:
            assert expected in str(e), e

    try:
        list(clam_utils.scan_path_streaming("/does/not/exist"))
        assert False, "missing path should have raised"
    except Exception as e:
        assert "Path not found" in str(e)


def test_cli_exit_codes():
    for output, code, expected_exit, expected_text in [
        (CLEAN, 0, 0, "No malware found"),
        (GOOD, 1, 1, "eicar.com Eicar-Test-Signature FOUND"),
        (BROKEN_DB, 2, 2, "Scan failed"),
    ]:
        fake(output, code)
        result = CliRunner().invoke(cli, ["clam", "scan", tempfile.gettempdir()])
        assert result.exit_code == expected_exit, (expected_text, result.exit_code, result.output)
        assert expected_text in result.output, result.output
        assert "No malware found" not in result.output or expected_exit == 0, result.output


if __name__ == "__main__":
    test_good_scan_classification()
    test_failed_scans_raise()
    test_cli_exit_codes()
    print("All clam scan checks passed")
