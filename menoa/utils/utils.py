# For app-wide utils
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

def progress_download(url, filename):
    print("Downloading", url)
    
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

    if os.path.exists(str(Path.home())+"/.local/share/applications/menoa.desktop"):
        return

    if not os.fileexists(str(Path.home())+"/.menoa/app_icon.png"):
        download_icon()
    
    with open(str(Path.home())+"/.local/share/applications/menoa.desktop", "w") as file:
            file.write("""[Desktop Entry]
    Name=Menoa
    Comment=Antivirus and security center
    Exec=menoa-gui
    Icon=~/.menoa/app_icon.png
    Terminal=false
    Type=Application
    Categories=Utility;Security;""")
        
def initialize_config():
    """
    For installs without a config, write a default one
    """

    home_path = str(Path.home())
    config_path = home_path + "/.menoa/config.toml"

    if not os.path.exists(home_path + "/.menoa/"):
        os.mkdir(home_path + '/.menoa/')

    if not os.path.exists(home_path + "/.menoa/clam_last_scanned/"):
        with open(home_path + '/.menoa/clam_last_scanned', 'w') as f:
            f.write("1970-01-01T00:00:00")

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

    [shell]

    [clam_feeds.default_daily]
    url = "http://127.0.0.1:5000/feeds/clam/daily.cvd"
    name = "Default daily.cvd ClamAV feed"
    description = "Daily signatures bundled with ClamAV"
    local_path = "~/.menoa/feeds/clam/daily.cvd"
    last_refreshed = 1970-01-01T00:00:00
    supports_versioning = true
    current_version = 1

    [clam_feeds.default_main]
    url = "http://127.0.0.1:5000/feeds/clam/main.cvd"
    name = "Default main.cvd ClamAV feed"
    description = "Main signatures database bundled with ClamAV"
    local_path = "~/.menoa/feeds/clam/main.cvd"
    last_refreshed = 1970-01-01T00:00:00
    supports_versioning = true
    current_version = 1

    [clam_feeds.default_bytecode]
    url = "http://127.0.0.1:5000/feeds/clam/bytecode.cvd"
    name = "Default bytecode.cvd ClamAV feed"
    description = "Bytecode database bundled with ClamAV"
    local_path = "~/.menoa/feeds/clam/bytecode.cvd"
    last_refreshed = 1970-01-01T00:00:00
    supports_versioning = true
    current_version = 1

    [network_feeds.main]
    url = "http://127.0.0.1:5000/feeds/network/main.csv"
    name = "Default Menoa network feed"
    description = "Menoa's malicious endpoint feed generated from open source feeds"
    local_path = "~/.menoa/feeds/network/main.csv"
    last_refreshed = 1970-01-01 00:00:00
    supports_versioning = false
    current_version = 1
    """

    with open(config_path, "w") as f:
        f.write(default_string)

    if not os.path.exists(home_path + "/.menoa/feeds/"):
        os.mkdir(home_path + '/.menoa/feeds')

    if not os.path.exists(home_path + "/.menoa/feeds/clam"):
        os.mkdir(home_path + '/.menoa/feeds/clam')

    if not os.path.exists(home_path + "/.menoa/feeds/clam/quick"):
        os.mkdir(home_path + '/.menoa/feeds/clam/quick')

    if not os.path.exists(home_path + "/.menoa/feeds/clam/standard"):
        os.mkdir(home_path + '/.menoa/feeds/clam/standard')

    if not os.path.exists(home_path + "/.menoa/feeds/clam/deep"):
        os.mkdir(home_path + '/.menoa/feeds/clam/deep')

    if not os.path.exists(home_path + "/.menoa/feeds/network"):
        os.mkdir(home_path + '/.menoa/feeds/network')

    # Download all the default feeds
    from menoa.utils.clam_utils import update_all_feeds as clam_update_all_feeds
    clam_update_all_feeds()

    from menoa.utils.network_utils import update_all_feeds as network_update_all_feeds
    network_update_all_feeds()

    # Symlink into quick/standard/deep
    clam_path = home_path+"/.menoa/feeds/clam"

    if not os.path.islink(clam_path + "/quick/daily.cvd"):
        os.symlink(clam_path + "/daily.cvd", clam_path + "/quick/daily.cvd")
    if not os.path.islink(clam_path + "/quick/bytecode.cvd"):
        os.symlink(clam_path + "/bytecode.cvd", clam_path + "/quick/bytecode.cvd")

    if not os.path.islink(clam_path + "/standard/main.cvd"):
        os.symlink(clam_path + "/main.cvd", clam_path + "/standard/main.cvd")
    if not os.path.islink(clam_path + "/standard/daily.cvd"):
        os.symlink(clam_path + "/daily.cvd", clam_path + "/standard/daily.cvd")
    if not os.path.islink(clam_path + "/standard/bytecode.cvd"):
        os.symlink(clam_path + "/bytecode.cvd", clam_path + "/standard/bytecode.cvd")

    if not os.path.islink(clam_path + "/deep/main.cvd"):
        os.symlink(clam_path + "/main.cvd", clam_path + "/deep/main.cvd")
    if not os.path.islink(clam_path + "/deep/daily.cvd"):
        os.symlink(clam_path + "/daily.cvd", clam_path + "/deep/daily.cvd")
    if not os.path.islink(clam_path + "/deep/bytecode.cvd"):
        os.symlink(clam_path + "/bytecode.cvd", clam_path + "/deep/bytecode.cvd")

def get_enabled_tools():
    """
    Returns a list of tools which are enabled
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    enabled = []

    if config["clamav"]["enabled"]: enabled.append("clam")
    if config["network"]["enabled"]: enabled.append("network")
    if config["process"]["enabled"]: enabled.append("process")
    if config["attestation"]["enabled"]: enabled.append("attestation")

    return enabled

def rewrite():
    """
    Rewrites ~/.menoa to default install
    """

    try:
        shutil.rmtree(str(Path.home())+"/.menoa")
    except:
        pass

    initialize_config()


def initialize():
    initialize_desktop_file()
    initialize_config()

"""
Init checks

- create dirs
- create config
- create desktop file
- create symlinks for quick/standard/deeps

"""