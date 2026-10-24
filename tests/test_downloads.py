"""
Checks downloads save bandwidth: unchanged files aren't sent again, gzip and .xz are decoded. Run with `python tests/test_downloads.py` (or pytest)
"""

import gzip, hashlib, lzma, os, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
(Path.home() / ".menoa").mkdir()

import joblib, tomli
from menoa.utils import utils, network_utils, process_utils


class Server(BaseHTTPRequestHandler):
    # Serves `files` like nginx or object storage would: an ETag per version, gzip-encoded unless it's already compressed
    files = {}
    requests = []  # (path, If-None-Match header, status)

    def do_GET(self):
        body = self.files.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        etag = f'"{hashlib.md5(body).hexdigest()}"'
        if self.headers.get("If-None-Match") == etag:
            self.requests.append((self.path, self.headers.get("If-None-Match"), 304))
            self.send_response(304)
            self.end_headers()
            return

        self.requests.append((self.path, self.headers.get("If-None-Match"), 200))
        self.send_response(200)
        self.send_header("ETag", etag)
        if not self.path.endswith(".xz"):
            body = gzip.compress(body)
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Server)
threading.Thread(target=server.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{server.server_port}"


def statuses(path):
    return [status for p, _, status in Server.requests if p == path]


def test_unchanged_files_are_skipped_and_gzip_decoded():
    Server.files["/sigs.hdb"] = b"44d88612fea8a8f36de82e1278abb02f:68:Test\n" * 1000
    stored = Path.home() / "sigs.hdb"
    calls = []

    assert utils.progress_download(URL + "/sigs.hdb", stored, lambda text, done, total: calls.append((done, total)), skip_unchanged=True) == stored
    assert stored.read_bytes() == Server.files["/sigs.hdb"]  # Decompressed
    assert calls[-1][0] == calls[-1][1] < len(Server.files["/sigs.hdb"]) / 10  # Progress counts the gzip bytes, matching Content-Length

    assert utils.progress_download(URL + "/sigs.hdb", stored, skip_unchanged=True) is None
    assert statuses("/sigs.hdb") == [200, 304]

    Server.files["/sigs.hdb"] = b"0123456789abcdef0123456789abcdef:10:Test2\n"
    assert utils.progress_download(URL + "/sigs.hdb", stored, skip_unchanged=True) == stored
    assert stored.read_bytes() == Server.files["/sigs.hdb"]

    # A deleted file is downloaded in full, not trusted to exist
    stored.unlink()
    utils.progress_download(URL + "/sigs.hdb", stored, skip_unchanged=True)
    assert stored.exists() and statuses("/sigs.hdb") == [200, 304, 200, 200]


def test_network_feed_refresh():
    Server.files["/ips.txt"] = b"203.0.113.5\n198.51.100.7\n"
    (Path.home() / ".menoa" / "config.toml").write_text(f'[network_feeds.test]\nformat = "plain"\nurl = "{URL}/ips.txt"\n')
    refreshed = lambda: tomli.loads((Path.home() / ".menoa" / "config.toml").read_text())["network_feeds"]["test"]["last_refreshed"]

    assert network_utils.update_feed("test") == 2
    first = refreshed()
    assert network_utils.update_feed("test") == 2  # Unchanged: the stored IPs are kept and still counted
    assert statuses("/ips.txt") == [200, 304] and refreshed() >= first

    # A broken upstream file keeps the old IPs, and the next refresh asks for the whole file again
    Server.files["/ips.txt"] = b"<html>oops</html>\n"
    try:
        network_utils.update_feed("test")
        assert False, "an empty feed should have raised"
    except Exception as e:
        assert "keeping previous data" in str(e), e
    assert network_utils.feed_cache_path("test").read_text() == "198.51.100.7\n203.0.113.5\n"
    Server.files["/ips.txt"] = b"192.0.2.1\n"
    assert network_utils.update_feed("test") == 1
    assert Server.requests[-1] == ("/ips.txt", None, 200)


def test_xz_model():
    key = Path(tempfile.mkdtemp()) / "model.key"
    public = process_utils.generate_signing_key(str(key))
    model = Path(tempfile.mkdtemp()) / "model.pkl"
    joblib.dump({"model": "compressed", "metadata": {"version": "1.0"}}, model)
    process_utils.sign_model(str(model), str(key))  # Signs the decompressed model
    Server.files["/model.pkl.xz"] = lzma.compress(model.read_bytes())
    Server.files["/model.pkl.sig"] = Path(str(model) + ".sig").read_bytes()
    (Path.home() / ".menoa" / "config.toml").write_text("[process]\nthreshold = 0.5\n")
    folder = Path(process_utils.MODEL_PATH).parent

    process_utils.set_model(URL + "/model.pkl.xz", public)
    assert process_utils.load_model()["model"] == "compressed"
    assert sorted(p.name for p in folder.glob("process_scanner*")) == ["process_scanner.pkl", "process_scanner.pkl.sig"]

    # A .xz that decompresses to more than the cap is rejected before it fills the disk
    Server.files["/huge.pkl.xz"] = lzma.compress(b"\0" * 5_000_000)
    with mock.patch.object(process_utils, "MAX_MODEL_BYTES", 1_000_000):
        try:
            process_utils.set_model(URL + "/huge.pkl.xz")
            assert False, "an oversized model should have raised"
        except Exception as e:
            assert "over 1 MB" in str(e), e
    assert process_utils.load_model()["model"] == "compressed"  # Still the previous model
    assert sorted(p.name for p in folder.glob("process_scanner*")) == ["process_scanner.pkl", "process_scanner.pkl.sig"]


def test_back_to_menoa_model():
    # `menoa process model --default` removes the user's model from the config, Menoa's bundled model is used again
    model = Path(tempfile.mkdtemp()) / "menoa.pkl"
    joblib.dump({"model": "menoa", "metadata": {"version": "0.2.0"}}, model)
    (Path.home() / ".menoa" / "config.toml").write_text(f'[process]\nthreshold = 0.5\nmodel_url = "{URL}/model.pkl.xz"\nmodel_public_key = "x"\n')
    with mock.patch.multiple(process_utils, BUNDLED_MODEL=model, BUILTIN_MODEL_SHA256=hashlib.sha256(model.read_bytes()).hexdigest()):
        process_utils.set_model()
        assert tomli.loads((Path.home() / ".menoa" / "config.toml").read_text())["process"] == {"threshold": 0.5}
        assert process_utils.load_model()["model"] == "menoa"


if __name__ == "__main__":
    test_unchanged_files_are_skipped_and_gzip_decoded()
    test_network_feed_refresh()
    test_xz_model()
    test_back_to_menoa_model()
    print("All download checks passed")
