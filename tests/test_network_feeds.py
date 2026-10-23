"""
Checks for the network feed formats. Run with `python tests/test_network_feeds.py` (or pytest)
Uses a temporary HOME so it never touches your real ~/.menoa
"""

import json, os, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
(Path.home() / ".menoa").mkdir()
(Path.home() / ".menoa" / "config.toml").write_text("[network_feeds]\n")

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


if __name__ == "__main__":
    test_normalize()
    test_formats_end_to_end()
    test_add_feed_validation()
    print("All network feed checks passed")
