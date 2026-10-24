"""
Checks for the network feed formats. Run with `python tests/test_network_feeds.py` (or pytest)
Uses a temporary HOME so it never touches your real ~/.menoa
"""

import json, os, sys, tempfile, threading
from types import SimpleNamespace
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
(Path.home() / ".menoa").mkdir()
(Path.home() / ".menoa" / "config.toml").write_text("[network_feeds]\n")

import psutil
from menoa.utils import network_utils as nu


class FakeMisp(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        ok = self.path == "/attributes/restSearch" and self.headers["Authorization"] == "secret" and body["returnFormat"] == "text"
        self.send_response(200 if ok else 403)
        self.end_headers()
        self.wfile.write(b"203.0.113.9\n2001:db8::1\n" if ok else b"denied")

    def log_message(self, *args):
        pass


def test_normalize():
    ips = nu.normalize_indicators([
        "1.2.3.4", "  5.6.7.8  # c2 server", "http://9.9.9.9:8080/payload.sh", "http://evil.example/x",
        "2001:DB8::2", "# comment", "", "not an ip", "127.0.0.1", "0.0.0.0", "224.0.0.1", "10.0.0.5",
    ])
    assert ips == {"1.2.3.4", "5.6.7.8", "9.9.9.9", "2001:db8::2", "10.0.0.5"}, ips


def test_formats_end_to_end():
    feed_dir = Path(tempfile.mkdtemp())
    (feed_dir / "list.txt").write_text("# my list\n198.51.100.1\n198.51.100.2\n")
    (feed_dir / "named.csv").write_text("ip,note\n198.51.100.3,bad\n")
    # Some feeds put the header inside a comment, so the column is picked by number
    (feed_dir / "urlhaus.csv").write_text('# id,dateadded,url\n"1","2026-01-01","http://198.51.100.4/x.sh"\n')

    server = HTTPServer(("127.0.0.1", 0), FakeMisp)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    os.environ["TEST_MISP_KEY"] = "secret"

    nu.add_feed("plain1", "n", "d", "plain", url=str(feed_dir / "list.txt"))
    nu.add_feed("csv1", "n", "d", "csv", url="file://" + str(feed_dir / "named.csv"), column="ip")
    nu.add_feed("csv2", "n", "d", "csv", url=str(feed_dir / "urlhaus.csv"), column=2)
    nu.add_feed("misp1", "n", "d", "misp", url=f"http://127.0.0.1:{server.server_port}/", api_key_env="TEST_MISP_KEY")
    nu.add_feed("cmd1", "n", "d", "command", command="printf '198.51.100.5\\n'")

    assert nu.update_feed("plain1") == 2
    assert nu.update_feed("csv1") == 1
    assert nu.update_feed("csv2") == 1
    assert nu.update_feed("misp1") == 2
    assert nu.update_feed("cmd1") == 1
    assert nu.reload_endpoints() == {"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "203.0.113.9", "2001:db8::1", "198.51.100.5"}

    # A feed that suddenly returns nothing must not wipe what was downloaded before
    (feed_dir / "list.txt").write_text("<html>error page</html>\n")
    try:
        nu.update_feed("plain1")
        assert False, "empty feed should raise"
    except Exception as e:
        assert "keeping previous data" in str(e)
    assert nu.get_number_of_threats_from_feed("plain1") == 2

    nu.remove_feed("cmd1")
    assert not nu.feed_cache_path("cmd1").exists()
    server.shutdown()


def test_add_feed_validation():
    for args, kwargs in [
        (("../x", "n", "d", "plain"), {"url": "/x"}),   # unsafe index
        (("ok", "n", "d", "rss"), {"url": "/x"}),       # unknown format
        (("ok", "n", "d", "csv"), {"url": "/x"}),       # csv without column
        (("ok", "n", "d", "misp"), {"url": "http://x"}),  # misp without key
    ]:
        try:
            nu.add_feed(*args, **kwargs)
            assert False, f"should have rejected {args} {kwargs}"
        except Exception as e:
            assert "should have rejected" not in str(e), e


def write_feeds(**feeds):
    # index -> its IPs, or None for a feed in the config that hasn't been downloaded
    (Path.home() / ".menoa" / "config.toml").write_text("".join(f'[network_feeds.{i}]\nformat = "plain"\nurl = "/nonexistent"\n' for i in feeds))
    for index, ips in feeds.items():
        path = nu.feed_cache_path(index)
        path.parent.mkdir(parents=True, exist_ok=True)
        if ips is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text("\n".join(ips) + "\n")


# What psutil.net_connections() reports: a listening socket has no remote address, other users' processes have no pid
CONNECTIONS = [
    SimpleNamespace(raddr=SimpleNamespace(ip="93.184.216.34", port=443), pid=os.getpid()),
    SimpleNamespace(raddr=SimpleNamespace(ip="::ffff:198.51.100.66", port=8080), pid=None),
    SimpleNamespace(raddr=SimpleNamespace(ip="2001:db8::bad", port=22), pid=os.getpid()),
    SimpleNamespace(raddr=(), pid=1),
]


def test_connections_check():
    write_feeds(main=["198.51.100.66", "2001:db8::bad"], other=None)
    alerts = []
    with mock.patch.object(psutil, "net_connections", lambda kind: CONNECTIONS), mock.patch.object(nu.utils, "alert", lambda *a: alerts.append(a)):
        results = nu.connections_check(desktop_notification=True)

    assert results == [
        {"pid": None, "process": "", "remote": "198.51.100.66:8080", "malicious": True},
        {"pid": os.getpid(), "process": psutil.Process().name(), "remote": "[2001:db8::bad]:22", "malicious": True},
        {"pid": os.getpid(), "process": psutil.Process().name(), "remote": "93.184.216.34:443", "malicious": False},
    ], results
    assert len(alerts) == 2 and "198.51.100.66:8080" in alerts[0][1]
    assert nu.missing_feeds() == ["other"]

    # No feed downloaded: nothing can be checked, which must never look like "all clear"
    write_feeds(main=None)
    try:
        nu.connections_check()
        assert False, "should have raised"
    except Exception as e:
        assert "No network feeds are downloaded" in str(e), e


def test_network_scan_cli():
    from click.testing import CliRunner
    from menoa.cli import cli

    with mock.patch.object(psutil, "net_connections", lambda kind: CONNECTIONS):
        write_feeds(main=["198.51.100.66"], other=None)
        result = CliRunner().invoke(cli, ["network", "scan"])
        assert result.exit_code == 1 and "198.51.100.66:8080" in result.stdout and "1 malicious connection" in result.stdout, result.output
        assert "other hasn't been downloaded" in result.stderr, result.output

        write_feeds(main=["192.0.2.200"])
        result = CliRunner().invoke(cli, ["network", "scan"])
        assert result.exit_code == 0 and "No malicious connections (3 checked)" in result.output, result.output

        write_feeds(main=None)
        result = CliRunner().invoke(cli, ["network", "scan"])
        assert result.exit_code == 2 and "NOT checked" in result.output, result.output


def test_network_page():
    from concurrent.futures import Future
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from menoa.pages.network_page import NetworkPage

    write_feeds(main=["198.51.100.66"])
    page = NetworkPage()
    page.timer.stop()  # Results are handed in below instead of scanned
    assert "eth0: UP" not in page.bottom_box.toPlainText() and "Interface Summary:" in page.bottom_box.toPlainText()

    def finish(result=None, error=None):
        page._future = Future()
        page._future.set_exception(error) if error else page._future.set_result(result)
        page.update_logs()

    with mock.patch.object(psutil, "net_connections", lambda kind: CONNECTIONS):
        finish(nu.connections_check())
    assert page.alert_label.text() == "1 malicious connection(s)!" and not page.alert_label.isHidden()
    log = page.log_box.toPlainText().splitlines()
    assert log[1].endswith("198.51.100.66:8080  MALICIOUS") and "MALICIOUS" not in log[2], log
    assert "#f44336" in page.log_box.toHtml().lower()  # Shown in red

    finish([{"pid": 1, "process": "<script>", "remote": "192.0.2.1:80", "malicious": False}])
    assert page.alert_label.isHidden() and "<script>" in page.log_box.toPlainText()  # Escaped, shown as text

    finish(error=Exception("No network feeds are downloaded"))
    assert "aren't being checked" in page.alert_label.text() and not page.alert_label.isHidden()
    page.executor.shutdown()


if __name__ == "__main__":
    test_normalize()
    test_formats_end_to_end()
    test_add_feed_validation()
    test_connections_check()
    test_network_scan_cli()
    test_network_page()
    print("All network feed checks passed")
