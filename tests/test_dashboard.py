"""
Checks that dashboard cards open their pages and show real statuses and stats. Run with `python tests/test_dashboard.py` (or pytest)
"""

import os, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
MENOA = Path.home() / ".menoa"
(MENOA / "feeds" / "clam").mkdir(parents=True)

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

app = QApplication.instance() or QApplication([])
from menoa.main import DashboardPage

TOOLS = ("clamav", "network", "process", "attestation")


def write_config(enabled):
    (MENOA / "config.toml").write_text("".join(f"[{tool}]\nenabled = {str(tool in enabled).lower()}\n" for tool in TOOLS)
                                       + '[clam_feeds.default_daily]\nlocal_path = "~/.menoa/feeds/clam/daily.cvd"\n')


def write_daily(age_days):
    built = int(time.time() - age_days * 86400)
    (MENOA / "feeds" / "clam" / "daily.cvd").write_bytes(f"ClamAV-VDB:20 Oct 2026 07-41 +0000:28160:2077386:90:md5:sig:builder:{built}".encode().ljust(512))


def statuses(page):
    return {card.title: card.status_label.text() for card in page.cards}


def stats(page):
    return {label: value.text() for label, value in page.stat_values.items()}


def test_cards_open_their_pages():
    write_config(TOOLS)
    page = DashboardPage()
    requested = []
    page.pageRequested.connect(requested.append)
    for card in page.cards:
        QTest.mouseClick(card, Qt.LeftButton)
    # Indexes of the pages in MainWidget's stack
    assert dict(zip([card.title for card in page.cards], requested)) == {
        "ClamAV Scanner": 1, "Endpoint Scanner": 2, "Process Scanner (beta)": 3, "Attestation (beta)": 4, "Command Predictor (beta)": 5,
    }, requested


def test_statuses_follow_the_config():
    write_config({"clamav", "attestation"})
    page = DashboardPage()
    assert statuses(page) == {
        "ClamAV Scanner": "Enabled", "Endpoint Scanner": "Disabled", "Process Scanner (beta)": "Disabled",
        "Attestation (beta)": "Enabled", "Command Predictor (beta)": "",
    }, statuses(page)
    assert stats(page)["Active Tools"] == "2"

    # Changed elsewhere (like `menoa process toggle --on`), shown when the dashboard is opened again
    write_config(TOOLS)
    page.show()
    assert stats(page)["Active Tools"] == "4" and statuses(page)["Process Scanner (beta)"] == "Enabled", stats(page)


def test_stats():
    write_config(TOOLS)
    last_scanned = MENOA / "clam_last_scanned"

    write_daily(3)
    page = DashboardPage()
    assert stats(page)["Signatures"] == "3 days old" and stats(page)["Last Scan"] == "Never", stats(page)

    (MENOA / "feeds" / "clam" / "daily.cvd").unlink()
    for placeholder in ("0", "1970-01-01T00:00:00"):  # Written by older versions of init
        last_scanned.write_text(placeholder)
        page.refresh()
        assert stats(page)["Signatures"] == "Not downloaded" and stats(page)["Last Scan"] == "Never", stats(page)

    last_scanned.write_text("2026-10-24 01:08:33 PM")
    page.refresh()
    assert stats(page)["Last Scan"] == "2026-10-24 01:08:33 PM", stats(page)


if __name__ == "__main__":
    test_cards_open_their_pages()
    test_statuses_follow_the_config()
    test_stats()
    print("All dashboard checks passed")
