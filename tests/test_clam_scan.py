"""
Checks that clam scans never report a failed scan as clean. Run with `python tests/test_clam_scan.py` (or pytest)
Uses a fake clamscan that replays real clamscan output, so no signature database is needed
"""

import os, stat, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
CLAM_DIR = Path.home() / ".menoa" / "feeds" / "clam"
CLAM_DIR.mkdir(parents=True)
DEFAULT_DBS = [str(CLAM_DIR / f"{db}.cvd") for db in ("daily", "main", "bytecode")]


def write_db(db="daily", age_days=0):
    # Real header layout, padded to 512 bytes like a .cvd. The last field is the build time the age is measured from
    built = int(time.time() - age_days * 86400)
    (CLAM_DIR / f"{db}.cvd").write_bytes(f"ClamAV-VDB:20 Oct 2026 07-41 +0000:28160:2077386:90:md5:sig:svc.clamav-publisher:{built}".encode().ljust(512))


for db in ("daily", "main", "bytecode"):
    (Path.home() / ".menoa" / "config.toml").open("a").write(f'[clam_feeds.default_{db}]\nlocal_path = "~/.menoa/feeds/clam/{db}.cvd"\n')
    write_db(db)

FAKE_BIN = Path(tempfile.mkdtemp())
ARGS_FILE = FAKE_BIN / "args"
(FAKE_BIN / "clamscan").write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {ARGS_FILE}\ncat "$FAKE_CLAM_OUT"\nexit "$FAKE_CLAM_EXIT"\n')
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

# What clamscan prints first when its database is over 7 days old
OLD_DB_BANNER = """LibClamAV Warning: **************************************************
LibClamAV Warning: ***  The virus database is older than 7 days!  ***
LibClamAV Warning: ***   Please update it as soon as possible.    ***
LibClamAV Warning: **************************************************
"""


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


def test_scan_total_matches_clamscan_lines():
    # Real clamscan printed 12 lines for this tree: 8 files, 3 symlinks (to a file, a dir, nothing), 1 unreadable dir, nothing for the fifo/socket
    import socket
    tree = Path(tempfile.mkdtemp())
    (tree / "sub" / "deeper").mkdir(parents=True)
    (tree / "realdir").mkdir()
    (tree / "locked").mkdir()
    for name in ["f1", "f2", "f3", "empty", "realdir/inside", "sub/deeper/g1", "sub/deeper/g2", "sub/deeper/g3"]:
        (tree / name).write_text("x")
    os.symlink(tree / "f1", tree / "link_file")
    os.symlink("/nonexistent", tree / "link_broken")
    os.symlink(tree / "realdir", tree / "link_dir")
    os.mkfifo(tree / "fifo")
    socket.socket(socket.AF_UNIX).bind(str(tree / "sock"))
    (tree / "locked" / "hidden").write_text("x")
    (tree / "locked").chmod(0)
    try:
        assert clam_utils.get_scan_total(str(tree)) == 12
        assert clam_utils.get_scan_total(str(tree / "f1")) == 1
    finally:
        (tree / "locked").chmod(stat.S_IRWXU)


def test_gui_progress():
    from menoa.pages.clam_page import Scanner
    folder = Path(tempfile.mkdtemp())
    for i in range(4):
        (folder / f"f{i}").write_text("x")
    lines = "".join(f"{folder}/f{i}: OK\n" for i in range(4))

    for output, code, expected in [
        (lines + SUMMARY.format(viruses=10), 0, [250, 500, 750, 999, 1000]),  # 100% only once clamscan has finished
        (lines + "LibClamAV Error: boom\n" + SUMMARY.format(viruses=0), 2, [250, 500, 750, 999]),  # failed scans never show 100%
    ]:
        fake(output, code)
        scanner = Scanner()
        scanner.set_scan_path(str(folder))
        values = []
        scanner.progress.connect(values.append)
        scanner.scan()
        assert values == expected, values


def test_custom_feeds_used():
    import threading
    from http.server import HTTPServer, SimpleHTTPRequestHandler
    from functools import partial

    # A custom feed served over http, downloaded with `clam reload`, then passed to clamscan
    served = Path(tempfile.mkdtemp())
    (served / "custom.hdb").write_text("44d88612fea8a8f36de82e1278abb02f:68:Menoa-Test\n")
    server = HTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(served)))
    threading.Thread(target=server.serve_forever, daemon=True).start()

    relative = os.path.relpath(Path.home() / "custom.hdb")
    clam_utils.add_feed("custom", "Custom", f"http://127.0.0.1:{server.server_port}/custom.hdb", "test", relative, move_into_default_feed_path=False)
    assert clam_utils.list_feeds()["custom"]["local_path"] == str(Path.home() / "custom.hdb")  # stored absolute

    # Not downloaded yet: skipped with a warning instead of breaking the whole scan
    fake(CLEAN, 0)
    items = list(clam_utils.scan_path_streaming(tempfile.gettempdir()))
    assert any(f is None and "Custom feed custom skipped" in r for f, r in items), items
    assert str(Path.home() / "custom.hdb") not in ARGS_FILE.read_text()

    assert CliRunner().invoke(cli, ["clam", "reload", "custom"]).exit_code == 0
    assert (Path.home() / "custom.hdb").exists()

    list(clam_utils.scan_path_streaming(tempfile.gettempdir()))
    args = ARGS_FILE.read_text().splitlines()
    assert args[args.index(str(Path.home() / "custom.hdb")) - 1] == "-d", args
    for db in DEFAULT_DBS:  # A custom feed is added to the ClamAV databases, never replaces them
        assert args[args.index(db) - 1] == "-d", args

    clam_utils.remove_feed("custom")
    server.shutdown()


def test_scans_use_menoa_databases():
    fake(CLEAN, 0)
    scan_all()
    args = ARGS_FILE.read_text().splitlines()
    assert args == ["-r", "-d", DEFAULT_DBS[0], "-d", DEFAULT_DBS[1], "-d", DEFAULT_DBS[2], tempfile.gettempdir()], args

    # Without a -d clamscan would fall back to the system database, so a missing download stops the scan
    os.rename(DEFAULT_DBS[0], DEFAULT_DBS[0] + ".bak")
    try:
        scan_all()
        assert False, "missing database should have raised"
    except Exception as e:
        assert "isn't downloaded" in str(e) and "menoa clam reload" in str(e), e
    finally:
        os.rename(DEFAULT_DBS[0] + ".bak", DEFAULT_DBS[0])


def test_database_version_without_clamscan():
    from PySide6.QtWidgets import QApplication
    from menoa.pages.clam_page import ClamPage

    path = os.environ["PATH"]
    os.environ["PATH"] = "/nonexistent"  # No clamscan anywhere
    try:
        assert clam_utils.get_database_version() == ("28160", "20 Oct 2026 07-41 +0000")
        app = QApplication.instance() or QApplication([])
        page = ClamPage()
        assert "DB Patch: 28160" in page.status1.text()

        os.rename(DEFAULT_DBS[0], DEFAULT_DBS[0] + ".bak")
        assert clam_utils.get_database_version() == ("Not downloaded", "never")
        page = ClamPage()
        assert "Not downloaded" in page.status1.text()
        os.rename(DEFAULT_DBS[0] + ".bak", DEFAULT_DBS[0])
    finally:
        os.environ["PATH"] = path


def test_database_freshness():
    try:
        for age, state, text in [(0.1, "fresh", "2 hours old"), (1, "outdated", "1 day old"), (3, "outdated", "3 days old"), (10, "critical", "10 days old"), (-1, "fresh", "0 hours old")]:
            write_db(age_days=age)
            assert clam_utils.database_freshness() == (state, f"Malware signatures are {text}"), (age, clam_utils.database_freshness())

        (CLAM_DIR / "daily.cvd").write_bytes(b"not a database")
        assert clam_utils.database_freshness()[0] == "unreadable"
        assert clam_utils.get_database_version() == ("Unreadable", "unknown")
        os.remove(CLAM_DIR / "daily.cvd")
        assert clam_utils.database_freshness()[0] == "missing"
    finally:
        write_db()


def test_outdated_warning():
    tmp = tempfile.gettempdir()
    fake(OLD_DB_BANNER + CLEAN, 0)
    try:
        write_db(age_days=10)
        # clamscan's own banner isn't reported as a file that couldn't be scanned
        assert [r for f, r in scan_all() if f is None] == []

        result = CliRunner().invoke(cli, ["clam", "scan", tmp])
        assert result.exit_code == 0, result.output
        assert "10 days old" in result.stderr and "10 days old" not in result.stdout, result.output  # Kept out of piped output
        assert "couldn't be scanned" not in result.output, result.output

        for command in (["clam", "scan", tmp, "--quiet"], ["clam", "scan", tmp, "-q"], ["clam", "quick", "--quiet"]):
            result = CliRunner().invoke(cli, command)
            assert "days old" not in result.output, (command, result.output)

        write_db()
        assert "old" not in CliRunner().invoke(cli, ["clam", "scan", tmp]).stderr
    finally:
        write_db()


def test_status_exit_codes():
    try:
        for age, exit_code, text in [(0, 0, "0 hours old"), (3, 1, "3 days old"), (10, 1, "10 days old")]:
            write_db(age_days=age)
            result = CliRunner().invoke(cli, ["clam", "status"])
            assert result.exit_code == exit_code and text in result.output and "28160" in result.output, result.output

        os.remove(CLAM_DIR / "daily.cvd")
        result = CliRunner().invoke(cli, ["clam", "status"])
        assert result.exit_code == 2 and "aren't downloaded" in result.output, result.output
    finally:
        write_db()


def test_gui_age_and_update():
    from PySide6.QtWidgets import QApplication
    from menoa.pages.clam_page import ClamPage
    from menoa.pages.progress_dialog import run_with_progress
    app = QApplication.instance() or QApplication([])

    try:
        write_db(age_days=10)
        page = ClamPage()
        assert page.db_age.text() == "Malware signatures are 10 days old, scans will miss newer malware", page.db_age.text()
    finally:
        write_db()

    # The task runs on a worker thread, its progress reaches the dialog, and an exception becomes a failure
    seen = []
    def task(progress):
        progress("Downloading daily.cvd", 5, 10)
        seen.append(1)
        return []
    assert run_with_progress(task, "Updating...") == [] and seen == [1]
    assert run_with_progress(lambda progress: 1 / 0, "Updating...") == ["division by zero"]


if __name__ == "__main__":
    test_custom_feeds_used()
    test_good_scan_classification()
    test_failed_scans_raise()
    test_cli_exit_codes()
    test_scan_total_matches_clamscan_lines()
    test_gui_progress()
    test_scans_use_menoa_databases()
    test_database_version_without_clamscan()
    test_database_freshness()
    test_outdated_warning()
    test_status_exit_codes()
    test_gui_age_and_update()
    print("All clam scan checks passed")
