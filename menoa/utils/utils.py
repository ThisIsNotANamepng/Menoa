"""
App-wide helpers: notifications, downloads, first-time setup and picking which feeds a scan uses
"""

import asyncio
from desktop_notifier import DesktopNotifier, Urgency, DEFAULT_SOUND, Icon
from pathlib import Path
import os
import pathlib
import shutil
import sys
import json
import requests
from urllib.parse import unquote
from tqdm.auto import tqdm
import tomli
from typing import Any, Callable, Dict, List, Optional, Sequence

# Menoa's icon, shipped inside the package (package_data in setup.py)
ICON_PATH = Path(__file__).resolve().parent.parent / "notification_icon.png"

def alert(title: Any, text: Any, type: str = "normal", location: str = "desktop") -> None:
    """
    Raises a notification of an alert, either in the app or on the desktop
    """
    title=str(title)
    text=str(text)

    if location=="desktop": asyncio.run(desktop_notification(title, text)) #desktop_notification(title, text)

async def desktop_notification(title: str, text: str) -> None:
    """
    Sends a critical desktop notification with Menoa's icon
    """
    notifier = DesktopNotifier(app_name="Menoa")
    icon = Icon(path=ICON_PATH)

    await notifier.send(
        title=title,
        message=text,
        urgency=Urgency.Critical,
        sound=DEFAULT_SOUND,
        icon=icon
    )

def _download_cache_path() -> Path:
    """
    Where the ETag and Last-Modified of every download are kept, see cached_headers()
    """
    return Path.home() / ".menoa" / "download_cache.json"

def _load_download_cache() -> Dict[str, Dict[str, Any]]:
    """
    Returns the download cache, empty if it's missing or unreadable
    """
    try:
        with open(_download_cache_path()) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

def _write_download_cache(cache: Dict[str, Dict[str, Any]]) -> None:
    """
    Saves the download cache, replaced in one step so a crash can't leave half a file
    """
    path = _download_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=1))
    os.replace(tmp, path)

def cached_headers(stored_file: Any, url: str) -> Dict[str, str]:
    """
    Headers asking the server to only send `url` if it changed since it was saved to `stored_file` (it answers 304 otherwise)
    """
    entry = _load_download_cache().get(str(stored_file))
    if not entry or entry.get("url") != url or not os.path.exists(stored_file):
        return {}
    headers = {"If-None-Match": entry.get("etag"), "If-Modified-Since": entry.get("last_modified")}
    return {k: v for k, v in headers.items() if v}

def save_validators(stored_file: Any, url: str, response: Any) -> None:
    """
    Remembers the response's ETag and Last-Modified for cached_headers()
    Call only once the response is stored in stored_file, or an unchanged reply later would keep a copy that was never written
    """
    cache = _load_download_cache()
    cache[str(stored_file)] = {"url": url, "etag": response.headers.get("ETag"), "last_modified": response.headers.get("Last-Modified")}
    _write_download_cache(cache)

def forget_validators(stored_file: Any) -> None:
    """
    Makes the next request download stored_file in full again
    """
    cache = _load_download_cache()
    if cache.pop(str(stored_file), None) is not None:
        _write_download_cache(cache)

def progress_download(url: str, filename: Any, progress: Optional[Callable[[str, int, int], None]] = None, skip_unchanged: bool = False) -> Optional[Path]:
    """
    Downloads `url` to `filename`, showing a terminal progress bar, or calling progress(text, done_bytes, total_bytes) instead if given
    With skip_unchanged, a file the server says hasn't changed since last time isn't downloaded again, and None is returned
    """
    path = pathlib.Path(filename).expanduser().resolve()
    name = unquote(url.rsplit("/", 1)[-1]).rsplit("/", 1)[-1]
    print("Downloading", url)

    headers = cached_headers(path, url) if skip_unchanged else {}
    r = requests.get(url, stream=True, allow_redirects=True, timeout=60, headers=headers)
    if r.status_code == 304:
        print(f"{name} hasn't changed")
        return None
    if r.status_code != 200:
        r.raise_for_status()
        raise RuntimeError(f"Request to {url} returned status code {r.status_code}")
    # The size on the wire, compressed if the server sends Content-Encoding: gzip
    file_size = int(r.headers.get('Content-Length', 0))

    path.parent.mkdir(parents=True, exist_ok=True)

    # Write then rename so an interrupted download can't leave a truncated file in place
    tmp = path.with_name(path.name + ".part")
    done = 0
    with tqdm(total=file_size or None, unit="B", unit_scale=True, desc=name, disable=progress is not None) as bar, tmp.open("wb") as f:
        for chunk in r.iter_content(chunk_size=1 << 16):  # Decompressed by requests
            f.write(chunk)
            wire = r.raw.tell()  # Bytes received, so progress matches Content-Length
            bar.update(wire - done)
            done = wire
            if progress:
                progress(f"Downloading {name}", done, file_size)
    os.replace(tmp, path)

    if skip_unchanged:
        save_validators(path, url, r)
    return path

def initialize_desktop_file() -> None:
    """
    Adds Menoa to the app menu. Rewritten every init, so it follows Menoa to wherever it's installed now
    """

    desktop_path = Path.home() / ".local" / "share" / "applications" / "menoa.desktop"

    # A copy outside the install folder, so the menu icon survives Menoa being reinstalled or its venv moved
    icon_path = Path.home() / ".menoa" / "app_icon.png"
    icon_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ICON_PATH, icon_path)

    # The app menu doesn't get the PATH of a venv or a terminal, so use the menoa-gui installed next to the running menoa command
    gui = Path(sys.argv[0]).absolute().parent / "menoa-gui"
    exec_path = str(gui) if gui.exists() else shutil.which("menoa-gui") or "menoa-gui"

    desktop_path.parent.mkdir(parents=True, exist_ok=True)
    # Desktop files don't expand ~, so the paths have to be absolute
    desktop_path.write_text(f"""[Desktop Entry]
Name=Menoa
Comment=Antivirus and security center
Exec="{exec_path}"
Icon={icon_path}
Terminal=false
Type=Application
Categories=System;Security;
""")

def initialize_config(progress: Optional[Callable[[str, int, int], None]] = None) -> List[str]:
    """
    Creates anything missing in ~/.menoa: writes a default config if there isn't one, then downloads feeds and the process model

    progress(text, done_bytes, total_bytes) is called as work happens, total_bytes is 0 when the size isn't known
    Returns a list of the steps that failed, a failed download doesn't stop the rest of setup
    """

    # = Config
    home_path = str(Path.home())
    config_path = home_path + "/.menoa/config.toml"

    os.makedirs(home_path + "/.menoa/", exist_ok=True)

    default_string = """
    [clamav]
    scan_delay = 600 # 10 minutes
    feed_update_delay = 21600 # 6 hours
    enabled = true

    [yara]
    scan_delay = 600 # 10 minutes
    feed_update_delay = 604800 # 1 week
    enabled = true

    [network]
    scan_delay = 10
    feed_update_delay = 21600 # 6 hours
    enabled = true

    [process]
    scan_delay = 600 # 10 minutes
    feed_update_delay = 86400 # 1 day
    enabled = true
    threshold = 0.7
    # Menoa's model is used unless you set your own, see `menoa process model`:
    # model_url = "<a URL or local path, a .xz is decompressed>"
    # model_public_key = "<only load it if signed with this key, see `menoa process sign`>"

    [attestation]
    scan_delay = 600 # 10 minutes
    enabled = true
    server_url = "" # Attestation server, see menoa/utils/attestation_utils.py for its API
    public_key = "" # Base64 Ed25519 public key the server's records are signed with

    [shell]

    [clam_feeds.default_daily]
    url = "https://database.clamav.net/daily.cvd" # Official ClamAV database, updated with cvdupdate (no root needed)
    name = "Default daily.cvd ClamAV feed"
    description = "Daily signatures bundled with ClamAV"
    local_path = "~/.menoa/feeds/clam/daily.cvd"
    last_refreshed = 1970-01-01T00:00:00

    [clam_feeds.default_main]
    url = "https://database.clamav.net/main.cvd" # Official ClamAV database, updated with cvdupdate (no root needed)
    name = "Default main.cvd ClamAV feed"
    description = "Main signatures database bundled with ClamAV"
    local_path = "~/.menoa/feeds/clam/main.cvd"
    last_refreshed = 1970-01-01T00:00:00

    [clam_feeds.default_bytecode]
    url = "https://database.clamav.net/bytecode.cvd" # Official ClamAV database, updated with cvdupdate (no root needed)
    name = "Default bytecode.cvd ClamAV feed"
    description = "Bytecode database bundled with ClamAV"
    local_path = "~/.menoa/feeds/clam/bytecode.cvd"
    last_refreshed = 1970-01-01T00:00:00

    [yara_feeds] # YARA rule files, run with YARA-X, see `menoa yara add`

    [network_feeds.main]
    format = "plain"
    url = "https://menoa-feeds.us-ord-1.linodeobjects.com/network/main.txt"
    name = "Default Menoa network feed"
    description = "Menoa's malicious endpoint feed generated from open source feeds"
    last_refreshed = 1970-01-01 00:00:00
    """

    # Never overwrite an existing config, it holds the user's feeds and settings
    if not os.path.exists(config_path):
        with open(config_path, "w") as f:
            f.write(default_string)

    for d in ["feeds/clam", "feeds/yara", "feeds/network"]:
        os.makedirs(home_path + "/.menoa/" + d, exist_ok=True)

    # = Downloads
    from menoa.utils.clam_utils import update_all_feeds as clam_update_all_feeds
    from menoa.utils.network_utils import update_all_feeds as network_update_all_feeds
    from menoa.utils.process_utils import install_process_model

    failures = []

    def step(text: str, fn: Callable[[], Any]) -> None:
        print(text)
        if progress:
            progress(text, 0, 0)
        try:
            fn()
        except Exception as e:
            print(f"{text} failed: {e}")
            failures.append(f"{text}: {e}")

    step("Downloading ClamAV signature databases", lambda: clam_update_all_feeds(progress))
    def network_feeds() -> None:
        failed = network_update_all_feeds()
        if failed:
            raise Exception("; ".join(failed))

    step("Downloading network threat feeds", network_feeds)

    import menoa.utils.yara_utils as yara_utils
    if yara_utils.list_feeds():  # None by default yet
        def yara_feeds() -> None:
            failed = yara_utils.update_all_feeds()
            if failed:
                raise Exception("; ".join(failed))
        step("Downloading YARA rules", yara_feeds)
    if not os.path.exists(home_path + "/.menoa/process_scanner.pkl"):
        step("Installing process scanning model", lambda: install_process_model(progress))

    # = Attestation
    import menoa.utils.attestation_utils as attestation_utils
    step("Checking attestation database", attestation_utils.create_table)

    return failures


FEED_LEVELS = ("quick", "standard", "deep")

def select_feeds(configured: Dict[str, Dict[str, Any]], feeds: Optional[Sequence[str]] = None, level: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Picks which of the configured feeds ({index: feed}) a scan uses, returned the same way:
    - feeds: exactly these, each a configured index or a path to a file that isn't in the config
    - level: the feeds up to that level, they nest (quick feeds are in every level, deep feeds only in deep). A feed with no level is quick
    - neither: every configured feed
    """
    if feeds:
        picked = {}
        for feed in feeds:
            path = os.path.expanduser(feed)
            if feed in configured:
                picked[feed] = configured[feed]
            elif os.path.isfile(path):
                picked[feed] = {"local_path": os.path.abspath(path)}
            else:
                raise Exception(f"Unknown feed {feed}, use a configured feed ({', '.join(configured) or 'none'}) or a path to a file")
        return picked
    if level:
        return {index: feed for index, feed in configured.items() if FEED_LEVELS.index(feed.get("level", "quick")) <= FEED_LEVELS.index(level)}
    return dict(configured)

def feeds_by_engine(engines: Sequence[str], feeds: Sequence[str] = (), level: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Which feeds each engine ("clam", "yara") scans with, {engine: [feed names]}, see select_feeds(). Raises for an unknown feed
    With several engines each of `feeds` goes to the engine it belongs to (a rule file path, .yar, to YARA), and an engine
    none of them belong to is left out
    """
    import menoa.utils.clam_utils as clam_utils
    import menoa.utils.yara_utils as yara_utils
    configured = {"clam": clam_utils.list_feeds(), "yara": yara_utils.list_feeds()}

    wanted = {engine: [] for engine in engines}
    for feed in feeds:
        is_yara = feed in configured["yara"] or (feed not in configured["clam"] and feed.endswith((".yar", ".yara")))
        wanted[engines[0] if len(engines) == 1 else ("yara" if is_yara else "clam")].append(feed)

    return {engine: list(select_feeds(configured[engine], wanted[engine], level)) for engine in engines if wanted[engine] or not feeds}

def get_enabled_tools() -> List[str]:
    """
    Returns the config sections of the tools which are enabled, like ["clamav", "network"]
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    # Configs from before YARA was its own tool don't have a [yara] section, it's on by default
    return [tool for tool in ("clamav", "yara", "network", "process", "attestation") if config.get(tool, {"enabled": True})["enabled"]]

def rewrite() -> List[str]:
    """
    Rewrites ~/.menoa to default install
    """

    try:
        shutil.rmtree(str(Path.home())+"/.menoa")
    except Exception as e:
        print(e)
        pass

    return initialize_config()

def initialize(progress: Optional[Callable[[str, int, int], None]] = None) -> List[str]:
    """
    Sets up a fresh install, see initialize_config(). Returns a list of the steps that failed
    """
    failures = []
    try:
        initialize_desktop_file()
    except Exception as e:
        print(f"Creating desktop entry failed: {e}")
        failures.append(f"Creating desktop entry: {e}")

    return failures + initialize_config(progress)

"""
Init checks

- create dirs
- create config
- create desktop file
- create symlinks for quick/standard/deeps

"""