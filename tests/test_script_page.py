"""
Checks the command page loads a script from a URL and analyzes it. Run with `python tests/test_script_page.py` (or pytest)
"""

import os, sys, tempfile, threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()


def test_load_from_url():
    from PySide6.QtWidgets import QApplication
    from menoa.pages.script_page import ScriptPage
    app = QApplication.instance() or QApplication([])

    site = Path(tempfile.mkdtemp())
    (site / "install.sh").write_text("#!/bin/sh\nrm -rf /tmp/menoa-test\n")
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(site)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"

    try:
        page = ScriptPage()
        page.load_url(f"{url}/install.sh")
        assert page.script_input.toPlainText() == (site / "install.sh").read_text()
        output = page.output_view.toPlainText()
        assert output.startswith(f"Script from {url}/install.sh\n\n") and "Deletes /tmp/menoa-test" in output, output

        # A failed download says why and keeps the script that was there
        page.load_url(f"{url}/missing.sh")
        assert page.script_input.toPlainText() == (site / "install.sh").read_text()
        output = page.output_view.toPlainText()
        assert output.startswith(f"Couldn't download {url}/missing.sh: 404"), output
    finally:
        server.shutdown()


if __name__ == "__main__":
    test_load_from_url()
    print("All script page checks passed")
