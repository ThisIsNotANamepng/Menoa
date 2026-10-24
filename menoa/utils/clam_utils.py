import subprocess
import shutil
import os
from typing import List, Tuple, Optional
from datetime import datetime
import tomli, tomli_w
from pathlib import Path
import requests

import menoa.utils.utils as utils

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

def scan_path_streaming(path: str):
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

    # Every scan type uses every configured database. A missing default stops the scan, without any -d clamscan would silently use the system database
    databases = []
    for index, feed in list_feeds().items():
        feed_path = os.path.expanduser(feed["local_path"])
        if os.path.exists(feed_path):
            databases += ["-d", feed_path]
        elif index in DEFAULT_CLAM_FEEDS:
            raise Exception(f"ClamAV database {feed_path} isn't downloaded, run `menoa clam reload`")
        else:
            yield (None, f"Custom feed {index} skipped, {feed_path} doesn't exist (run `menoa clam reload {index}`)")

    if not databases:
        raise Exception("No ClamAV databases in ~/.menoa/config.toml")
    cmd += databases

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
            elif line.startswith("LibClamAV Warning: *"):
                continue  # clamscan's "database is older than 7 days" banner, Menoa reports the age itself (database_freshness)
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

def read_database_header():
    """
    Returns the header fields of Menoa's daily database, None if it isn't downloaded, [] if it isn't a ClamAV database
    """

    path = os.path.expanduser(list_feeds().get("default_daily", {}).get("local_path", "~/.menoa/feeds/clam/daily.cvd"))
    try:
        with open(path, "rb") as f:
            # ClamAV-VDB:build date:version:signatures:functionality level:md5:signature:builder:build time, padded to 512 bytes
            header = f.read(512).decode("ascii", "replace").strip().split(":")
    except FileNotFoundError:
        return None

    return header if header[0] == "ClamAV-VDB" and len(header) >= 9 else []

def get_database_version():
    """
    Returns (version, build date) of Menoa's daily database, read from its header so clamscan isn't needed
    """

    header = read_database_header()
    if header is None:
        return ("Not downloaded", "never")
    if not header:
        return ("Unreadable", "unknown")
    return (header[2], header[1])

OUTDATED_AFTER_DAYS = 1  # ClamAV publishes a new daily database several times a day, older means updates aren't running
CRITICAL_AFTER_DAYS = 7  # Where clamscan itself starts warning

def database_freshness():
    """
    Returns (state, text) for Menoa's daily database, state is "fresh", "outdated", "critical", "missing" or "unreadable"
    and text describes it, like "Malware signatures are 3 days old"
    """

    header = read_database_header()
    if header is None:
        return ("missing", "ClamAV databases aren't downloaded")
    try:
        built = int(header[8])
    except (IndexError, ValueError):
        return ("unreadable", "Menoa's daily.cvd isn't a readable ClamAV database")

    age = max(datetime.now().timestamp() - built, 0) / 86400
    if age < 1:
        amount, unit = int(age * 24), "hour"
    else:
        amount, unit = int(age), "day"
    text = f"Malware signatures are {amount} {unit}{'' if amount == 1 else 's'} old"

    if age >= CRITICAL_AFTER_DAYS:
        return ("critical", text)
    if age >= OUTDATED_AFTER_DAYS:
        return ("outdated", text)
    return ("fresh", text)

def get_last_time_scanned():
    # Returns the last time the system was scanned

    try:
        with open(str(Path.home())+"/.menoa/clam_last_scanned", "r") as file:
            return file.read()
    except FileNotFoundError:
        return "Never"

def set_last_time_scanned():
    # Updates the last time the system was scanned

    with open(str(Path.home())+"/.menoa/clam_last_scanned", "w") as file:
        file.write(datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"))

def get_scan_total(path):
    """
    Counts the result lines clamscan will print for `path`, for progress bars:
    one per file and per symlink (it doesn't follow them), one per directory it can't open, none for fifos or sockets
    """

    if not os.path.isdir(path):
        return 1

    total = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.is_symlink() or entry.is_file(follow_symlinks=False):
                    total += 1
                elif entry.is_dir(follow_symlinks=False):
                    total += get_scan_total(entry.path)
    except OSError:
        return 1  # clamscan prints "Can't open directory." once for it
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

    # Scans run from any directory, so a relative path would point somewhere else later
    local_path = os.path.abspath(os.path.expanduser(local_path))

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