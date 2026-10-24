# For app-wide utils
import asyncio
import signal
from desktop_notifier import DesktopNotifier, Urgency, Button, ReplyField, DEFAULT_SOUND, Icon
from pathlib import Path
import os
import pathlib
import shutil
import requests
from urllib.parse import unquote
from tqdm.auto import tqdm
import tomli

def alert(title, text, type="normal", location="desktop"):
    """
    Raises a notification of an alert, either in the app or on the desktop
    """
    title=str(title)
    text=str(text)

    if location=="desktop": asyncio.run(desktop_notification(title, text)) #desktop_notification(title, text)

async def desktop_notification(title, text) -> None:
    notifier = DesktopNotifier(app_name="Menoa")
    icon_path = Path("/home/jack/code/Menoa/menoa/notification_icon.png")
    icon = Icon(path=icon_path)

    await notifier.send(
        title=title,
        message=text,
        urgency=Urgency.Critical,
        sound=DEFAULT_SOUND,
        icon=icon
    )

def get_patch_number(url):
    # Takes a url and returns the patch number

    return int(url.split("/")[-1].split("_")[1].split(".")[0])


def combine_files(source_file, destination_file):
    try:
        with open(source_file, 'rb') as source_file:
            with open(destination_file, 'ab') as destination_file:
                while True:
                    chunk = source_file.read(1024)
                    if not chunk:
                        break
                    destination_file.write(chunk)
        
    except Exception as e:
        print(f"Error: {e}")

def progress_download(url, filename, progress=None):
    """
    Downloads `url` to `filename`, showing a terminal progress bar, or calling progress(text, done_bytes, total_bytes) instead if given
    """
    print("Downloading", url)

    r = requests.get(url, stream=True, allow_redirects=True, timeout=60)
    if r.status_code != 200:
        r.raise_for_status()
        raise RuntimeError(f"Request to {url} returned status code {r.status_code}")
    file_size = int(r.headers.get('Content-Length', 0))

    path = pathlib.Path(filename).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    name = unquote(url.rsplit("/", 1)[-1]).rsplit("/", 1)[-1]

    # Write then rename so an interrupted download can't leave a truncated file in place
    tmp = path.with_name(path.name + ".part")
    done = 0
    with tqdm(total=file_size or None, unit="B", unit_scale=True, desc=name, disable=progress is not None) as bar, tmp.open("wb") as f:
        for chunk in r.iter_content(chunk_size=1 << 16):
            f.write(chunk)
            done += len(chunk)
            bar.update(len(chunk))
            if progress:
                progress(f"Downloading {name}", done, file_size)
    os.replace(tmp, path)

    return path

def progress_patch_download(url, filename, current_version):
    """
    Downloads a feed patch with a progress bar
    """
    try:
        response = requests.post(
            url,
            json={'current_version': current_version}
        )
        print(response.text)
        response.raise_for_status()
        #print(f"Response: {response.text}")
        urls = response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Request failed: {e}")

    print(response.text)

    try: urls = urls["urls"]
    except: raise Exception(f"Cannot reach {url}")
    sorted_urls = sorted(urls, key=get_patch_number)
    new_version = 0

    for url in sorted_urls:
        # Download patch into /tmp file, combine with main feed file
        new_version = get_patch_number(url)
        print(f"Patch {new_version}")

        progress_download(url, "/tmp/menoa-tmp-feed-download")
        combine_files("/tmp/menoa-tmp-feed-download", filename)
        os.remove("/tmp/menoa-tmp-feed-download")

    return new_version

def download_icon():
    """
    Downloads an image from `url` and saves it to ~/.menoa/app_icon.png
    """

    target = Path.home() / ".menoa" / "app_icon.png"
    target.parent.mkdir(parents=True, exist_ok=True)

    r = requests.get("https://menoa.org/static/images/logo.png", stream=True, timeout=15)
    r.raise_for_status()

    with open(target, "wb") as fh:
        for chunk in r.iter_content(chunk_size=8192):
            fh.write(chunk)

    return target

def initialize_desktop_file():

    desktop_path = Path.home() / ".local" / "share" / "applications" / "menoa.desktop"
    if desktop_path.exists():
        return

    icon_path = Path.home() / ".menoa" / "app_icon.png"
    if not icon_path.exists():
        download_icon()

    desktop_path.parent.mkdir(parents=True, exist_ok=True)
    # Desktop files don't expand ~, so the icon path has to be absolute
    desktop_path.write_text(f"""[Desktop Entry]
Name=Menoa
Comment=Antivirus and security center
Exec=menoa-gui
Icon={icon_path}
Terminal=false
Type=Application
Categories=Utility;Security;
""")

def initialize_config(progress=None):
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

    [network]
    scan_delay = 10
    feed_update_delay = 21600 # 6 hours
    enabled = true

    [process]
    scan_delay = 600 # 10 minutes
    feed_update_delay = 86400 # 1 day
    enabled = true
    threshold = 0.7

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
    supports_versioning = true
    current_version = 1

    [clam_feeds.default_main]
    url = "https://database.clamav.net/main.cvd" # Official ClamAV database, updated with cvdupdate (no root needed)
    name = "Default main.cvd ClamAV feed"
    description = "Main signatures database bundled with ClamAV"
    local_path = "~/.menoa/feeds/clam/main.cvd"
    last_refreshed = 1970-01-01T00:00:00
    supports_versioning = true
    current_version = 1

    [clam_feeds.default_bytecode]
    url = "https://database.clamav.net/bytecode.cvd" # Official ClamAV database, updated with cvdupdate (no root needed)
    name = "Default bytecode.cvd ClamAV feed"
    description = "Bytecode database bundled with ClamAV"
    local_path = "~/.menoa/feeds/clam/bytecode.cvd"
    last_refreshed = 1970-01-01T00:00:00
    supports_versioning = true
    current_version = 1

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

    for d in ["feeds/clam", "feeds/network"]:
        os.makedirs(home_path + "/.menoa/" + d, exist_ok=True)

    # = Downloads
    from menoa.utils.clam_utils import update_all_feeds as clam_update_all_feeds
    from menoa.utils.network_utils import update_all_feeds as network_update_all_feeds
    from menoa.utils.process_utils import download_process_model

    failures = []

    def step(text, fn):
        print(text)
        if progress:
            progress(text, 0, 0)
        try:
            fn()
        except Exception as e:
            print(f"{text} failed: {e}")
            failures.append(f"{text}: {e}")

    step("Downloading ClamAV signature databases", lambda: clam_update_all_feeds(progress))
    def network_feeds():
        failed = network_update_all_feeds()
        if failed:
            raise Exception("; ".join(failed))

    step("Downloading network threat feeds", network_feeds)
    if not os.path.exists(home_path + "/.menoa/process_scanner.pkl"):
        step("Downloading process scanning model", lambda: download_process_model(progress))

    # = Attestation
    import menoa.utils.attestation_utils as attestation_utils
    step("Checking attestation database", attestation_utils.create_table)

    return failures


def get_enabled_tools():
    """
    Returns the config sections of the tools which are enabled, like ["clamav", "network"]
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return [tool for tool in ("clamav", "network", "process", "attestation") if config[tool]["enabled"]]

def rewrite():
    """
    Rewrites ~/.menoa to default install
    """

    try:
        shutil.rmtree(str(Path.home())+"/.menoa")
    except Exception as e:
        print(e)
        pass

    return initialize_config()

def initialize(progress=None):
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