# For application-wide utils
import asyncio
import signal
from desktop_notifier import DesktopNotifier, Urgency, Button, ReplyField, DEFAULT_SOUND, Icon
from pathlib import Path
import os
import functools
import pathlib
import shutil
import requests
from tqdm.auto import tqdm

def alert(title, text, type="normal", location="desktop"):
    """
    Raises a notification of an alert, either in the app or on the desktop
    """
    title=str(title)
    text=str(text)

    if location=="desktop": asyncio.run(desktop_notification(title, text)) #desktop_notification(title, text)


async def desktop_notification(title, text) -> None:
    notifier = DesktopNotifier(app_name="Menoa")
    icon_path = Path("/home/jack/code/LinuxSecuritySystem/gui/notification_icon.png")
    icon = Icon(path=icon_path)

    await notifier.send(
        title=title,
        message=text,
        urgency=Urgency.Critical,
        sound=DEFAULT_SOUND,
        icon=icon
    )

def progress_download(url, filename):
    
    r = requests.get(url, stream=True, allow_redirects=True)
    if r.status_code != 200:
        r.raise_for_status()
        raise RuntimeError(f"Request to {url} returned status code {r.status_code}")
    file_size = int(r.headers.get('Content-Length', 0))

    path = pathlib.Path(filename).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    desc = "(Unknown total file size)" if file_size == 0 else ""
    r.raw.read = functools.partial(r.raw.read, decode_content=True)  # Decompress if needed
    with tqdm.wrapattr(r.raw, "read", total=file_size, desc=desc) as r_raw:
        with path.open("wb") as f:
            shutil.copyfileobj(r_raw, f)

    return path

def initialize_config():
    """
    For installs without a config, write a default one
    """

    home_path = str(Path.home())

    if not os.path.exists(home_path + "/.menoa/"):
        os.mkdir(home_path + '/.menoa')

    if not os.path.exists(home_path + "/.menoa/feeds/"):
        os.mkdir(home_path + '/.menoa/feeds')

    config_path = home_path + "/.menoa/config.toml"

    default_string = """
    [clamav]
    scan_delay = 600 # 10 minutes
    feed_update_delay = 21600 # 6 hours
    enabled = true

    [network]
    scan_delay = 10
    feed_update_delay = 21600 # 6 hours
    enabled = true

    [process]
    scan_delay = 600 # 10 minutes
    feed_update_delay = 86400 # 1 day
    enabled = true

    [attestation]
    scan_delay = 600 # 10 minutes
    enabled = true

    [shell]

    [clam_feeds.default_daily]
    url = "http://127.0.0.1:5000/feeds/clam/daily.cld"
    name = "Default daily.cld ClamAV feed"
    description = "Daily signatures bundled with ClamAV"
    local_path = "~/.menoa/feeds/daily.cld"
    last_refreshed = 1970-01-01T00:00:00
    supports_versioning = true

    [clam_feeds.default_main]
    url = "http://127.0.0.1:5000/feeds/clam/main.cvd"
    name = "Default main.cvd ClamAV feed"
    description = "Main signatures database bundled with ClamAV"
    local_path = "~/.menoa/feeds/main.cvd"
    last_refreshed = 1970-01-01T00:00:00
    supports_versioning = true

    [clam_feeds.default_bytecode]
    url = "http://127.0.0.1:5000/feeds/clam/bytecode.cvd"
    name = "Default bytecode.cvd ClamAV feed"
    description = "Bytecode database bundled with ClamAV"
    local_path = "~/.menoa/feeds/bytecode.cvd"
    last_refreshed = 1970-01-01T00:00:00
    supports_versioning = true

    [network_feeds.main]
    url = "http://127.0.0.1:5000/feeds/network/main.csv"
    name = "Default Menoa network feed"
    description = "Menoa's malicious endpoint feed generated from open source>
    local_path = "~/.menoa/feeds/network/main.csv"
    last_refreshed = 1970-01-01 00:00:00
    supports_versioning = true


    """

    with open(config_path, "w") as f:
        f.write(default_string)