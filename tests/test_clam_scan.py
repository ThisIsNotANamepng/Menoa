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

import tomli
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

# What clamscan prints on a terminal while it loads its signatures: "\r" redraws the line, escape codes toggle line wrapping
PROGRESS = ("Loading:     0s               [                         ]        0/3.29M sigs    \r"
            "\x1b[?7lLoading:     1s, ETA:   0s [==========>              ]    1.39M/3.29M sigs    \x1b[?7h\r"
            "Loading:     2s, ETA:   0s [========================>]    3.29M/3.29M sigs    \r\n"
            "Compiling:   1s, ETA:   0s [===========>             ]       20/41 tasks \r"
            "Compiling:   2s, ETA:   0s [========================>]       41/41 tasks \r\n")

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


def test_gui_updates_on_gui_thread():
    # The page's progress handler must run on the GUI thread, not the scan's worker thread
    import threading
    from PySide6.QtWidgets import QApplication
    from menoa.pages.clam_page import ClamPage, CircularProgress
    app = QApplication.instance() or QApplication([])

    folder = Path(tempfile.mkdtemp())
    for i in range(4):
        (folder / f"f{i}").write_text("x")
    fake("".join(f"{folder}/f{i}: OK\n" for i in range(4)) + SUMMARY.format(viruses=10), 0)

    # Records which thread moves the progress circle. Not a QLabel: PySide6 runs a Python override of a Qt slot on the emitting thread
    threads = []
    class RecordingCircle(CircularProgress):
        def setValue(self, value, engine="clam"):
            threads.append(threading.current_thread())
            super().setValue(value, engine)

    page = ClamPage()
    page.circular = RecordingCircle()
    page._start_scan(str(folder))
    end = time.time() + 30
    while time.time() < end and (page._running or not threads):
        app.processEvents()
        time.sleep(0.01)
    assert threads and all(t is threading.main_thread() for t in threads), threads
    assert page.circular._values == {"clam": 1000, "yara": None}  # No YARA feeds, so only ClamAV ran


def test_clamscan_progress_and_summary():
    fake(PROGRESS + CLEAN, 0)
    events, summaries = [], []
    items = list(clam_utils.scan_path_streaming(tempfile.gettempdir(), lambda *e: events.append(e), summaries.append))

    assert [(stage, round(done), round(total)) for stage, done, total in events] == [
        ("Loading signatures", 0, 3290000), ("Loading signatures", 1390000, 3290000), ("Loading signatures", 3290000, 3290000),
        ("Compiling signatures", 20, 41), ("Compiling signatures", 41, 41),
    ], events
    assert items == [("/t/sub/a.txt", "OK"), ("/t/empty.txt", "Empty file")], items  # Progress lines never show up as results
    assert summaries == [{"Known viruses": "10", "Engine version": "1.4.4", "Scanned files": "2"}], summaries

    # A filename that isn't valid UTF-8 is passed on like Python passes filesystem paths, not an error
    output = Path(tempfile.mkstemp()[1])
    output.write_bytes(b"/t/caf\xe9.txt: OK\n" + SUMMARY.format(viruses=10).encode())
    os.environ["FAKE_CLAM_OUT"], os.environ["FAKE_CLAM_EXIT"] = str(output), "0"
    [(file, result)] = scan_all()
    assert os.fsencode(file) == b"/t/caf\xe9.txt" and result == "OK"


def test_gui_log_shows_loading():
    from menoa.pages.clam_page import Scanner
    fake(PROGRESS + CLEAN, 0)
    scanner = Scanner()
    scanner.set_scan_path(tempfile.gettempdir())
    log, status = [], []
    scanner.log.connect(log.append)
    scanner.status.connect(status.append)
    scanner.scan()
    assert log[:2] == ["Loading signatures...", "Compiling signatures..."], log
    assert log[-1].startswith("ClamAV: scanned 2 files with 10 signatures"), log
    assert "Loading signatures: 42%" in status and status[-1].startswith("Completed"), status


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

    assert clam_utils.list_feeds()["custom"]["last_refreshed"].year == 1970
    assert CliRunner().invoke(cli, ["clam", "reload", "custom"]).exit_code == 0
    assert (Path.home() / "custom.hdb").exists()
    assert clam_utils.list_feeds()["custom"]["last_refreshed"].year > 1970

    # Each reload replaces the whole file, so signatures removed upstream go away and nothing piles up
    (served / "custom.hdb").write_text("0123456789abcdef0123456789abcdef:10:Menoa-Test-2\n")
    os.utime(served / "custom.hdb", (time.time() + 60,) * 2)  # A later upload, this test server only sends Last-Modified (whole seconds)
    assert CliRunner().invoke(cli, ["clam", "reload", "custom"]).exit_code == 0
    assert (Path.home() / "custom.hdb").read_text() == "0123456789abcdef0123456789abcdef:10:Menoa-Test-2\n"
    assert not list(Path.home().glob("custom.hdb.*"))  # No leftover temporary files

    list(clam_utils.scan_path_streaming(tempfile.gettempdir()))
    args = ARGS_FILE.read_text().splitlines()
    assert args[args.index(str(Path.home() / "custom.hdb")) - 1] == "-d", args
    for db in DEFAULT_DBS:  # A custom feed is added to the ClamAV databases, never replaces them
        assert args[args.index(db) - 1] == "-d", args

    clam_utils.remove_feed("custom")
    server.shutdown()


def make_yara_feeds():
    # YARA-X supports modules (elf), uint32be and duplicate rule names across feeds, unlike ClamAV's YARA parser
    from menoa.utils import yara_utils
    rules = Path(tempfile.mkdtemp())
    (rules / "one.yar").write_text('import "elf"\n'
                                   'rule Marker { strings: $a = "menoa-yara-marker" condition: $a }\n'
                                   'rule ElfMagic { condition: uint32be(0) == 0x7f454c46 and elf.number_of_sections > 0 }\n'
                                   'rule Broken { condition: oops( }\n')  # Left out, the rest of the file still loads
    (rules / "two.yara").write_text('rule Marker { strings: $a = "menoa-other-marker" condition: $a }\n')
    yara_utils.add_feed("one", "One", "", "test", str(rules / "one.yar"))  # Local rule files, no url
    yara_utils.add_feed("two", "Two", "", "test", str(rules / "two.yara"))
    return rules


def make_yara_folder():
    import shutil
    folder = Path(tempfile.mkdtemp())
    (folder / "marked.txt").write_text("hello menoa-yara-marker")
    (folder / "other.txt").write_text("menoa-other-marker")
    (folder / "clean.txt").write_text("nothing here")
    shutil.copy(os.path.realpath(sys.executable), folder / "program")
    (folder / "link.txt").symlink_to(folder / "marked.txt")  # Checked where it's stored, not twice
    os.mkfifo(folder / "pipe")  # Opening it would hang the scan
    return folder


def test_yara_tool():
    import psutil
    from menoa.utils import yara_utils

    # No feeds: a YARA scan fails clearly, and the combined scan runs ClamAV alone instead of failing
    folder = make_yara_folder()
    fake(CLEAN, 0)
    result = CliRunner().invoke(cli, ["yara", "scan", str(folder)])
    assert result.exit_code == 2 and "No YARA feeds to scan with, add one" in result.output, result.output
    result = CliRunner().invoke(cli, ["scan", "-q", str(folder)])
    assert result.exit_code == 0 and "ClamAV only" in result.stderr, result.output

    rules = make_yara_feeds()
    assert sorted(yara_utils.list_feeds()) == ["one", "two"] and "clam_feeds" in tomli.loads((Path.home() / ".menoa" / "config.toml").read_text())
    assert not any(feed.endswith((".yar", ".yara")) for feed in ARGS_FILE.read_text().splitlines())  # Never handed to clamscan

    stages, summary = [], {}
    items = list(yara_utils.scan_path_streaming(str(folder), lambda *e: stages.append(e[0]), summary.update))
    results = dict(items)
    assert results == {
        str(folder / "marked.txt"): "YARA.Marker FOUND", str(folder / "other.txt"): "YARA.Marker FOUND",
        str(folder / "program"): "YARA.ElfMagic FOUND", str(folder / "clean.txt"): "OK",
        str(folder / "link.txt"): "Symbolic link", str(folder / "pipe"): "Not a regular file",
    }, items
    assert len(items) == yara_utils.count_files(str(folder))  # One result per file, so progress reaches the end
    assert summary["YARA rules"] == "3" and summary["Scanned files"] == "4" and stages == ["Compiling YARA rules"], (summary, stages)

    # A symlink given directly is scanned where it points, like clamscan does
    (folder.parent / f"{folder.name}-link").symlink_to(folder / "marked.txt")
    assert list(yara_utils.scan_path_streaming(str(folder.parent / f"{folder.name}-link"))) == [(str(folder / "marked.txt"), "YARA.Marker FOUND")]

    # CLI: YARA alone, and both engines at once (ClamAV's fake output is clean, YARA finds the markers)
    result = CliRunner().invoke(cli, ["yara", "scan", str(folder)])
    assert result.exit_code == 1 and "with 3 YARA rules" in result.output and "marked.txt YARA.Marker FOUND" in result.output, result.output
    result = CliRunner().invoke(cli, ["scan", "-q", str(folder)])
    assert result.exit_code == 1 and "ClamAV: Scanned" in result.output and "YARA: Scanned" in result.output, result.output
    result = CliRunner().invoke(cli, ["clam", "scan", "-q", str(folder)])
    assert result.exit_code == 0 and "YARA" not in result.output, result.output
    assert CliRunner().invoke(cli, ["scan", str(folder), "--full"]).exit_code == 2  # A path or --quick/--full, not both

    # A feed that downloaded as an error page is reported, not silently scanned without
    (rules / "two.yara").write_text("<html><body>404 Not Found</body></html>\n")
    assert (None, f"No YARA rules could be loaded from {rules / 'two.yara'}") in list(yara_utils.scan_path_streaming(str(folder)))
    (rules / "two.yara").write_text('rule Marker { strings: $a = "menoa-other-marker" condition: $a }\n')

    # A caller that stops reading early (the GUI closing) doesn't leave YARA-X running
    scan = yara_utils.scan_path_streaming(str(folder))
    next(scan)
    scan.close()
    assert not [p for p in psutil.Process().children(recursive=True) if "menoa.utils.yara_utils" in " ".join(p.cmdline())]


def test_gui_scans_with_both_engines():
    import threading
    from PySide6.QtWidgets import QApplication
    from menoa.pages.clam_page import ClamPage
    app = QApplication.instance() or QApplication([])

    folder = make_yara_folder()
    fake("".join(f"{folder}/{name}: OK\n" for name in ("marked.txt", "other.txt", "clean.txt", "program")) + SUMMARY.format(viruses=10), 0)

    def run(page, *args):
        page._start_scan(str(folder), *args)
        end = time.time() + 30
        while time.time() < end and page._running:
            app.processEvents()
            time.sleep(0.01)
        app.processEvents()  # The final status comes right after finished

    page = ClamPage()
    run(page)  # The main buttons use both engines once there are YARA feeds
    assert page.circular._values == {"clam": 1000, "yara": 1000}, page.circular._values
    log = page.log_box.toPlainText()
    assert f"YARA: {folder}/marked.txt YARA.Marker FOUND" in log and f"YARA: {folder}/clean.txt" not in log, log
    assert page.status1.text() == "ClamAV: Completed: No threats found\nYARA: Completed: 3 threat(s) found", page.status1.text()

    run(page, ("yara",))  # YARA alone fills only the outer ring
    assert page.circular._values == {"clam": None, "yara": 1000} and page.status1.text() == "Completed: 3 threat(s) found"

    from menoa.utils import yara_utils
    for index in list(yara_utils.list_feeds()):
        yara_utils.remove_feed(index)


def test_feed_selection():
    from PySide6.QtWidgets import QApplication
    from menoa.utils import yara_utils
    from menoa.utils.utils import select_feeds
    from menoa.pages.clam_page import ClamPage
    app = QApplication.instance() or QApplication([])

    # Levels nest, a feed without one is quick
    configured = {"q": {"local_path": "/q"}, "s": {"local_path": "/s", "level": "standard"}, "d": {"local_path": "/d", "level": "deep"}}
    assert list(select_feeds(configured, level="quick")) == ["q"]
    assert list(select_feeds(configured, level="standard")) == ["q", "s"]
    assert list(select_feeds(configured, level="deep")) == list(select_feeds(configured)) == ["q", "s", "d"]
    try:
        select_feeds(configured, ["nope"])
        assert False, "an unknown feed should have raised"
    except Exception as e:
        assert "Unknown feed nope" in str(e), e

    (CLAM_DIR / "extra.hdb").write_text("44d88612fea8a8f36de82e1278abb02f:68:Menoa-Test\n")
    clam_utils.add_feed("extra", "Extra", "", "test", str(CLAM_DIR / "extra.hdb"), move_into_default_feed_path=False, level="deep")
    rules = make_yara_feeds()
    folder = make_yara_folder()
    fake(CLEAN, 0)
    databases = lambda: [line for line in ARGS_FILE.read_text().splitlines() if line.startswith("/") and line != str(folder)]

    # --feed: only those feeds, defaults included only if named, and the header says which are used
    result = CliRunner().invoke(cli, ["clam", "scan", "-q", str(folder), "--feed", "extra"])
    assert result.exit_code == 0 and "ClamAV feeds: extra" in result.output and databases() == [str(CLAM_DIR / "extra.hdb")], (result.output, databases())
    result = CliRunner().invoke(cli, ["clam", "scan", "-q", str(folder), "--level", "standard"])
    assert result.exit_code == 0 and str(CLAM_DIR / "extra.hdb") not in databases() and len(databases()) == 3, databases()
    result = CliRunner().invoke(cli, ["clam", "scan", "-q", str(folder), "--feed", "nope"])
    assert result.exit_code == 2 and "Unknown feed nope" in result.output, result.output

    # A YARA rule file that isn't in the config, and in a scan with both engines a YARA feed alone leaves ClamAV out
    result = CliRunner().invoke(cli, ["yara", "scan", str(folder), "--feed", str(rules / "two.yara")])
    assert result.exit_code == 1 and f"YARA feeds: {rules / 'two.yara'}" in result.output and "marked.txt" not in result.output, result.output
    result = CliRunner().invoke(cli, ["scan", "-q", str(folder), "--feed", "one"])
    assert result.exit_code == 1 and "scanning with YARA only" in result.stderr and "ClamAV: Scanned" not in result.output, result.output

    # GUI: the picker's choice is shown, logged and used
    page = ClamPage()
    assert page.feeds_used.text() == "ClamAV: default_daily, default_main, default_bytecode, extra\nYARA: one, two", page.feeds_used.text()
    page.feed_choice.setCurrentIndex(1)  # Quick level feeds
    page._feed_choice_changed(1)
    assert "extra" not in page.feeds_used.text()
    page.feed_choice.setCurrentIndex(4)  # Choose feeds... with only "two" ticked
    page._last_choice, page._chosen_feeds = 4, ["two"]
    page._show_feeds_used()
    assert page.feeds_used.text() == "YARA: two", page.feeds_used.text()
    page._start_scan(str(folder))
    end = time.time() + 30
    while time.time() < end and page._running:
        app.processEvents()
        time.sleep(0.01)
    log = page.log_box.toPlainText()
    assert "scanning with YARA only" in log and "YARA feeds: two" in log and "YARA.Marker FOUND" in log and "marked.txt" not in log, log
    page._chosen_feeds = []
    page._start_scan(str(folder))
    assert "SCAN NOT STARTED: no ClamAV or YARA feeds selected" in page.log_box.toPlainText()

    clam_utils.remove_feed("extra")
    for index in list(yara_utils.list_feeds()):
        yara_utils.remove_feed(index)


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


FAKE_MOUNTS = r"""/dev/nvme0n1p2 / ext4 rw 0 0
proc /proc proc rw 0 0
sysfs /sys sysfs rw 0 0
debugfs /sys/kernel/debug debugfs rw 0 0
udev /dev devtmpfs rw 0 0
devpts /dev/pts devpts rw 0 0
tmpfs /dev/shm tmpfs rw 0 0
tmpfs /tmp tmpfs rw 0 0
systemd-1 /boot/efi autofs rw 0 0
/dev/nvme0n1p1 /boot/efi vfat rw 0 0
systemd-1 /mnt/backup autofs rw 0 0
nas:/share /mnt/nas nfs4 rw 0 0
//nas/media /mnt/my\040share cifs rw 0 0
/dev/loop1 /snap/firefox/1 squashfs ro 0 0
/dev/sdb1 /media/jack/USB vfat rw 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw 0 0
"""


def test_skipped_mounts():
    from unittest import mock
    with mock.patch("builtins.open", mock.mock_open(read_data=FAKE_MOUNTS)):
        # Virtual, network and merged views are skipped. /dev, tmpfs, snaps, USB drives and a mounted autofs point are scanned
        assert clam_utils.skipped_mounts("/") == [
            "/dev/pts", "/mnt/backup", "/mnt/my share", "/mnt/nas", "/proc", "/sys", "/sys/kernel/debug", "/var/lib/docker/overlay2/abc/merged"]
        assert clam_utils.skipped_mounts("/sys/") == ["/sys/kernel/debug"]
        assert clam_utils.skipped_mounts("/proc") == []  # Scanning one directly still works
        assert clam_utils.skipped_mounts("/mn") == []    # Not a prefix match on names


def test_scans_skip_mounts():
    from unittest import mock
    tree = Path(tempfile.mkdtemp())
    for name in ["a", "virtual/b", "virtual/c", "virtual.d/e"]:
        (tree / name).parent.mkdir(exist_ok=True)
        (tree / name).write_text("x")

    with mock.patch.object(clam_utils, "skipped_mounts", lambda path: [str(tree / "virtual")]):
        # clamscan prints one "Excluded" line for a skipped directory, and its regex mustn't match virtual.d
        assert clam_utils.get_scan_total(str(tree)) == 3
        fake(CLEAN, 0)
        list(clam_utils.scan_path_streaming(str(tree)))
        args = ARGS_FILE.read_text().splitlines()
        assert args[:2] == ["-r", f"--exclude-dir=^{tree}/virtual$"], args
        assert clam_utils.exclude_regex("/x/virtual") == "^/x/virtual$"
        assert clam_utils.exclude_regex("/a.b+c(d)[e]{f}^g$h|i*j?k") == r"^/a\.b\+c\(d\)\[e\]\{f\}\^g\$h\|i\*j\?k$"


if __name__ == "__main__":
    test_custom_feeds_used()
    test_yara_tool()
    test_gui_scans_with_both_engines()
    test_feed_selection()
    test_good_scan_classification()
    test_failed_scans_raise()
    test_cli_exit_codes()
    test_scan_total_matches_clamscan_lines()
    test_gui_progress()
    test_gui_updates_on_gui_thread()
    test_clamscan_progress_and_summary()
    test_gui_log_shows_loading()
    test_scans_use_menoa_databases()
    test_database_version_without_clamscan()
    test_database_freshness()
    test_outdated_warning()
    test_status_exit_codes()
    test_gui_age_and_update()
    test_skipped_mounts()
    test_scans_skip_mounts()
    print("All clam scan checks passed")
