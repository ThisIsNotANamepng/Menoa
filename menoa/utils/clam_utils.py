import subprocess
import shutil
import os
from typing import List, Tuple, Optional
from datetime import datetime
import tomli, tomli_w
from pathlib import Path
import requests

#import utils.utils as utils

def is_clamscan_available() -> bool:
    """Check if clamscan is installed and available in PATH."""
    return shutil.which("clamscan") is not None

def is_freshclam_available() -> bool:
    """Check if freshclam (database updater) is installed."""
    return shutil.which("freshclam") is not None

def scan_path(path: str, recursive: bool = True) -> Tuple[bool, List[Tuple[str, str]]]:
    """
    Scan a file or directory using clamscan.
    
    Returns a tuple (success, results), where results is a list of (filename, result) tuples.
    """
    if not is_clamscan_available():
        return False, [("ERROR", "clamscan not found in PATH.")]

    if not os.path.exists(path):
        return False, [("ERROR", f"Path not found: {path}")]

    cmd = ["clamscan"]
    if recursive:
        cmd.append("-r")
    cmd.append(path)

    try:
        process = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        # clamscan exits with non-zero status if infection is found
        output = e.stdout
    else:
        output = process.stdout

    results = parse_clamscan_output(output)
    return True, results

CLEAN_RESULTS = ("OK", "Empty file", "Symbolic link", "Excluded")

def result_kind(file, result):
    """
    Classifies an item from scan_path_streaming() as "infected", "clean", or "error" (a file or engine problem, the file wasn't checked)
    """
    if file and result.endswith(" FOUND"):
        return "infected"
    if file and result in CLEAN_RESULTS:
        return "clean"
    return "error"

def scan_path_streaming(path: str, scan_type="standard"):
    """
    Generator that streams clamscan output line-by-line.
    Yields (filename, result) for each file as it's scanned, and (None, message) for engine warnings/errors, see result_kind()

    Raises an Exception once the scan ends if it couldn't actually check anything (no signatures loaded, clamscan crashed),
    so a failed scan is never mistaken for a clean one
    """

    # Absolute paths make every file line start with "/", which is how they're told apart from engine messages
    path = os.path.abspath(path)

    if not is_clamscan_available():
        raise Exception("clamscan not found in PATH, install ClamAV")

    if not os.path.exists(path):
        raise Exception(f"Path not found: {path}")

    cmd = ["clamscan"]

    if os.path.isdir(path):
        cmd.append("-r")

    if scan_type == "quick":
        for feed in os.listdir(str(Path.home())+"/.menoa/feeds/clam/quick/"):
            cmd.append("-d")
            cmd.append(str(Path.home())+"/.menoa/feeds/clam/quick/"+feed)

    elif scan_type == "standard":
        for feed in os.listdir(str(Path.home())+"/.menoa/feeds/clam/standard/"):
            cmd.append("-d")
            cmd.append(str(Path.home())+"/.menoa/feeds/clam/standard/"+feed)

    elif scan_type == "deep":
        for feed in os.listdir(str(Path.home())+"/.menoa/feeds/clam/deep/"):
            cmd.append("-d")
            cmd.append(str(Path.home())+"/.menoa/feeds/clam/deep/"+feed)

    cmd.append(path)

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    messages = []
    summary = None

    try:
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            if line.startswith("----------- SCAN SUMMARY"):
                summary = {}
            elif summary is not None:
                key, _, value = line.partition(": ")
                summary[key] = value
            elif line.startswith("/") and ": " in line:
                file, result = line.rsplit(": ", 1)
                yield (file, result)
            else:
                messages.append(line)
                yield (None, line)

        process.wait()
    finally:
        # Stop clamscan if the caller stops reading early
        if process.poll() is None:
            process.kill()

    if summary is None:
        raise Exception(f"clamscan exited with code {process.returncode} before finishing: " + " | ".join(messages[-5:]))

    if summary.get("Known viruses", "0") == "0":
        raise Exception("No malware signatures could be loaded, so nothing was scanned: " + " | ".join(messages[-5:]))

def get_clamav_version() -> str:
    """Return the version of clamscan if available."""
    if not is_clamscan_available():
        raise Exception("Clamscan is not available") 

    try:
        result = subprocess.run(["clamscan", "-V"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

def get_database_version():
    # Returns the database patch version and when it was last changed

    full = get_clamav_version().split("/")

    return (full[1], full[2])

def get_last_time_scanned():
    # Returns the last time the system was scanned

    last_scanned = ""

    with open(str(Path.home())+"/.menoa/clam_last_scanned", "r") as file:
        last_scanned = file.read()

    return last_scanned

def set_last_time_scanned():
    # Updates the last time the system was scanned

    with open(str(Path.home())+"/.menoa/clam_last_scanned", "w") as file:
        file.write(datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"))

def get_scan_total(path):

    if not os.path.isdir(path):
        return 1

    total = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.is_file():
                    total += 1
                elif entry.is_dir(follow_symlinks=False):
                    total += get_scan_total(entry.path)
    except PermissionError:
        pass  # Skip folders/files menoa can't access
    return total
    
DEFAULT_CLAM_FEEDS = ("default_main", "default_daily", "default_bytecode")

def update_all_feeds(progress=None):

    with open(str(Path.home())+"/.menoa/config.toml", "r") as file:
        config = file.read()

    toml_dict = tomli.loads(config)

    # One cvdupdate run fetches all three default databases
    if any(i in DEFAULT_CLAM_FEEDS for i in toml_dict['clam_feeds']):
        update_clamav_feed(progress)

    for i in toml_dict['clam_feeds'].keys():
        if i not in DEFAULT_CLAM_FEEDS:
            update_feed(i)

def update_feed(index):
    """
    Updates a feed using the given index which could be a title (as in the "default_daily" in [clam_feeds.default_daily] from the config)
    """

    if index in DEFAULT_CLAM_FEEDS:
        update_clamav_feed()
        return

    with open(str(Path.home())+"/.menoa/config.toml", "r") as file:
        config = file.read()

    toml_dict = tomli.loads(config)

    try:
        feed = (toml_dict["clam_feeds"][index])
    except KeyError:
        raise Exception("Error: Feed does not exist")

    if feed["supports_versioning"]:
        new_version = utils.progress_patch_download(feed['url'], feed["local_path"].replace("~", str(Path.home())), feed["current_version"])
        ##TODO: Add logic to update the current_version in the config file
    else:
        utils.progress_download(feed['url'], feed["local_path"].replace("~", str(Path.home())))

def _streaming_get(progress):
    """
    A requests.get for cvdupdate that streams the body so progress(text, done_bytes, total_bytes) can be reported
    shortcut: relies on cvdupdate only calling requests.get and reading response.content (true for the pinned 1.1.3), recheck when upgrading cvdupdate
    """

    def get(url, **kwargs):
        kwargs.setdefault("timeout", 60)
        response = requests.get(url, stream=True, **kwargs)
        name = url.rsplit("/", 1)[-1]
        total = int(response.headers.get("content-length", 0))

        data = bytearray()
        for chunk in response.iter_content(chunk_size=1 << 16):
            data += chunk
            if name.endswith((".cvd", ".cdiff")):
                progress(f"Downloading {name}", len(data), total)

        response._content = bytes(data)
        return response

    return get

def update_clamav_feed(progress=None):
    """
    Updates the feed using cvdupdate, which uses clamav's servers

    Only used for clamav feeds bytecode.cvd, main.cvd, daily.cvd (downloaded as daily.cvd)

    Assumes that all clamav default feed files are in ~/.menoa/feeds/clam/

    progress(text, done_bytes, total_bytes) is called while each database downloads, if given
    """
    # Run cvdupdate in-process, the `cvdupdate` command isn't on PATH for pipx installs or desktop launches
    import cvdupdate.cvdupdate as cvd
    from types import SimpleNamespace
    from unittest import mock

    print("Updating clamav feeds...")

    # Set the database directory to the feed dir instead of the default /var/lib/clamav
    updater = cvd.CVDUpdate(db_dir=str(Path.home())+"/.menoa/feeds/clam")

    if progress:
        with mock.patch.object(cvd, "requests", SimpleNamespace(get=_streaming_get(progress), exceptions=requests.exceptions)):
            errors = updater.db_update()
    else:
        errors = updater.db_update()

    if errors:
        raise Exception(f"cvdupdate failed to update {errors} database(s), see the cvdupdate log in ~/.cvdupdate/logs")

    # cvdupdate makes a dns.txt and some .cdiff files, we need to delete those
    path = Path(str(Path.home())+"/.menoa/feeds/clam/")
    if Path(Path(str(Path.home())+"/.menoa/feeds/clam/dns.txt")).is_file():
        os.remove(str(Path.home())+"/.menoa/feeds/clam/dns.txt")

    for file_path in path.glob("*.cdiff"):
        file_path.unlink()

def add_feed(index, name, url, description, local_path, supports_versioning=False, move_into_default_feed_path=True):
    """
    Adds a clam feed from the config
    if `move_into_default_feed_path` is True Menoa will try to copy the given filepath into `~/.menoa/feeds/clam/xxxx``
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    if index in config["clam_feeds"].keys():
        raise Exception("Error: Feed with index", index, "already exists. This identifier must be unique")

    if move_into_default_feed_path: # Copy filepath into local feed storage
        new_path = str(Path.home())+"/.menoa/feeds/clam/"+Path(local_path).name
        shutil.copy2(local_path, new_path)
        local_path = new_path

    config["clam_feeds"][index] = {
        "url": url,
        "name": name,
        "description": description,
        "local_path": local_path,
        "last_refreshed": "1970-01-01T00:00:00",
        "supports_versioning": supports_versioning
    }

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

def remove_feed(index):
    """
    Removes a clam feed from the config
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    if index not in config["clam_feeds"].keys():
        raise Exception("Given feed index not found in config")

    config["clam_feeds"].pop(index)

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

def list_feeds():
    """
    Returns a dictionary with all of the clam feeds
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["clam_feeds"]

def get_delay():
    """
    Returns the delay for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["clamav"]

def set_scanning_delay(seconds):
    """
    Sets the delay for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["clamav"]["scan_delay"] = seconds

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)


def set_feed_update_delay(seconds):
    """
    Sets the delay for refresh
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["clamav"]["feed_update_delay"] = seconds

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)
        
def toggle(status=None):
    """
    Toggles scanning, reverses current status if nothing is passed
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    current = config["clamav"]["enabled"]

    if status is None:
        config["clamav"]["enabled"] = not current
    else:
        config["clamav"]["enabled"] = status

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

    if status is None: return not current
    else: return status