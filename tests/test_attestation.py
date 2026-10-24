"""
Checks binary attestation against a fake signing server. Run with `python tests/test_attestation.py` (or pytest)
Uses a temporary HOME and binary directory, so it never touches your real ~/.menoa or /bin
"""

import base64, hashlib, json, os, sqlite3, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
(Path.home() / ".menoa").mkdir()

from menoa.utils import attestation_utils as au
import menoa.utils.utils as utils

KEY = Ed25519PrivateKey.generate()
WRONG_KEY = Ed25519PrivateKey.generate()
PUBLIC_KEY = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
DISTRO, ARCH = au.system_identity()

KNOWN = {}             # (package, version, path) -> the sha256 the fake server vouches for
SIGN_WITH_WRONG_KEY = set()
REQUESTS = []          # every binaries list the server received


class FakeServer(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        REQUESTS.append(body["binaries"])
        records = {}
        for b in body["binaries"]:
            sha = KNOWN.get((b["package"], b["version"], b["path"]))
            if sha:
                key = WRONG_KEY if b["path"] in SIGN_WITH_WRONG_KEY else KEY
                sig = key.sign(au.signed_message(body["distro"], body["arch"], b["package"], b["version"], b["path"], sha))
                records[b["path"]] = {"sha256": sha, "signature": base64.b64encode(sig).decode()}
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"records": records}).encode())

    def log_message(self, *args):
        pass


server = HTTPServer(("127.0.0.1", 0), FakeServer)
threading.Thread(target=server.serve_forever, daemon=True).start()
SERVER_URL = f"http://127.0.0.1:{server.server_port}"

def write_config(url):
    (Path.home() / ".menoa" / "config.toml").write_text(
        f'[attestation]\nscan_delay = 600\nenabled = true\nserver_url = "{url}"\npublic_key = "{PUBLIC_KEY}"\n')

BIN = Path(tempfile.mkdtemp())
au.BIN_DIR = str(BIN)
OWNERS = {}            # path -> (package, version), stands in for the package manager
au.get_package_owners = lambda paths: {p: OWNERS[p] for p in paths if p in OWNERS}
ALERTS = []
utils.alert = lambda title, text, **kw: ALERTS.append(text)

def binary(name, content, package=None, version=None, server_knows=True):
    path = str(BIN / name)
    Path(path).write_bytes(content)
    if package:
        OWNERS[path] = (package, version)
        if server_knows:
            KNOWN[(package, version, path)] = hashlib.sha256(content).hexdigest()
    return path

def statuses():
    return {Path(p).name: s for p, _, _, s in au.get_binary_data()}

def db(sql, args=()):
    conn = sqlite3.connect(au.DB_PATH)
    conn.execute(sql, args)
    conn.commit()
    conn.close()

def attest_expecting_error(text):
    try:
        au.attest()
        assert False, f"expected error containing {text!r}"
    except Exception as e:
        assert text in str(e), e


def test_attestation_flow():
    write_config(SERVER_URL)
    a = binary("a", b"real a", "pkg-a", "1.0")
    b = binary("b", b"real b", "pkg-b", "1.0")
    binary("c", b"not from a package")
    os.symlink(a, BIN / "link-to-a")  # a symlink to a binary that's already checked isn't checked twice
    elsewhere = Path(tempfile.mkdtemp()) / "multicall"  # like Ubuntu's coreutils, linked from /bin but living elsewhere
    elsewhere.write_bytes(b"real multicall")
    OWNERS[str(elsewhere)] = ("pkg-m", "1.0")
    KNOWN[("pkg-m", "1.0", str(elsewhere))] = hashlib.sha256(b"real multicall").hexdigest()
    os.symlink(elsewhere, BIN / "ls")

    # First check: owned binaries are attested, unowned ones can't be
    assert au.attest() == {"Validated": 3, "Not checkable": 1}
    assert statuses() == {"a": "Validated", "b": "Validated", "c": "Not checkable", "multicall": "Validated"}
    assert len(REQUESTS) == 1 and {x["path"] for x in REQUESTS[0]} == {a, b, str(elsewhere)}

    # Already attested binaries aren't sent again
    au.attest()
    assert len(REQUESTS) == 1

    # Binary changed but its package version didn't: tampered, and the user is alerted
    Path(a).write_bytes(b"malware")
    au.attest()
    assert statuses()["a"] == "Tampered!" and ALERTS

    # Malware rewrites the stored expected hash to match itself: the signature no longer matches
    db("UPDATE binaries SET expected_hash = ? WHERE path = ?", (hashlib.sha256(b"malware").hexdigest(), a))
    assert statuses()["a"] == "Record tampered!"

    # Malware copies b's valid record onto a (and b's content into a): records are bound to their path
    Path(a).write_bytes(b"real b")
    db("UPDATE binaries SET expected_hash = (SELECT expected_hash FROM binaries WHERE path = ?), "
       "signature = (SELECT signature FROM binaries WHERE path = ?) WHERE path = ?", (b, b, a))
    au.attest()
    assert statuses()["a"] == "Record tampered!"

    # Package upgrade: the old version's record is replaced, so storage stays one row per binary
    binary("a", b"real a v2", "pkg-a", "2.0")
    au.attest()
    assert statuses()["a"] == "Validated"
    assert au.get_number_of_binaries() == 4

    # Server hasn't indexed a version yet: Pending, and asked again next time instead of cached
    binary("b", b"real b v3", "pkg-b", "3.0", server_knows=False)
    au.attest()
    assert statuses()["b"] == "Pending"
    before = len(REQUESTS)
    au.attest()
    assert len(REQUESTS) == before + 1 and REQUESTS[-1][0]["path"] == b

    # A record signed with the wrong key is rejected and reported
    d = binary("d", b"real d", "pkg-d", "1.0")
    SIGN_WITH_WRONG_KEY.add(d)
    attest_expecting_error("invalid signatures")
    assert statuses()["d"] == "Pending"

    # Deleted binaries are removed from the database
    os.remove(b)
    os.remove(d)
    au.attest()
    assert set(statuses()) == {"a", "c", "multicall"}

    # Server down: the local check still runs and saves, then the error is reported
    write_config("http://127.0.0.1:9")
    Path(a).write_bytes(b"malware again")
    binary("e", b"real e", "pkg-e", "1.0")
    attest_expecting_error("Couldn't get records")
    assert statuses() == {"a": "Tampered!", "c": "Not checkable", "e": "Pending", "multicall": "Validated"}

    # No public key configured: nothing can show as Validated
    write_config(SERVER_URL)
    (Path.home() / ".menoa" / "config.toml").write_text('[attestation]\nscan_delay = 600\nenabled = true\nserver_url = "x"\npublic_key = ""\n')
    assert "Validated" not in statuses().values()
    attest_expecting_error("Set server_url and public_key")


def test_gui_stays_responsive():
    import time
    from unittest import mock
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from menoa.pages import attestation_page

    write_config(SERVER_URL)
    seen = {}

    def slow_attest():
        seen["thread"] = threading.current_thread()
        time.sleep(0.5)
        return {"Validated": 3, "Pending": 1}

    messages = []
    capture = lambda kind: (lambda parent, title, text: messages.append((kind, text)))
    with mock.patch.object(attestation_page, "attest", slow_attest), \
         mock.patch.object(attestation_page.QMessageBox, "information", capture("info")), \
         mock.patch.object(attestation_page.QMessageBox, "warning", capture("warning")):
        page = attestation_page.AttestationPage()
        QTimer.singleShot(100, lambda: seen.setdefault("gui_ran_during_check", True))
        page.run_attestation()
        assert seen["thread"] is not threading.main_thread() and seen.get("gui_ran_during_check"), seen
        assert messages == [("info", "Pending: 1\nValidated: 3")], messages

        def failing_attest():
            raise Exception("Attestation server unreachable")
        with mock.patch.object(attestation_page, "attest", failing_attest):
            page.run_attestation()
        assert messages[-1] == ("warning", "Attestation server unreachable"), messages


if __name__ == "__main__":
    test_attestation_flow()
    test_gui_stays_responsive()
    print("All attestation checks passed")
