"""
YARA rule scanning with YARA-X, a tool of its own next to ClamAV: `menoa yara`, the [yara] and [yara_feeds] config sections
YARA-X supports the whole YARA language, unlike ClamAV's own YARA parser (no modules like pe and elf, no uint32be,
and a long string can make it skip the rest of a file)

Scans run in their own process (python -m menoa.utils.yara_utils), like clamscan, so a crash on a malicious file stays out of Menoa
"""

import os, stat, subprocess, sys, time
from datetime import datetime
from pathlib import Path
import tomli, tomli_w

import menoa.utils.utils as utils

DEFAULT_SETTINGS = {"scan_delay": 600, "feed_update_delay": 604800, "enabled": True}
FEED_DIR = "~/.menoa/feeds/yara"
# shortcut: clamscan's default limit, so both engines skip the same big files, make it a setting if someone needs bigger files checked
MAX_FILE_SIZE = 100 * 1024 * 1024
TIMEOUT = 60  # Seconds per file
RULES_MARKER = "#rules"  # Sent in place of a file name with the rule count, real file names are absolute paths

def _load():
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)
    # Configs from before YARA was its own tool don't have these sections
    config["yara"] = {**DEFAULT_SETTINGS, **config.get("yara", {})}
    config.setdefault("yara_feeds", {})
    return config

def _save(config):
    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

# = Settings

def get_delay():
    return _load()["yara"]

def set_scanning_delay(seconds):
    config = _load()
    config["yara"]["scan_delay"] = seconds
    _save(config)

def set_feed_update_delay(seconds):
    config = _load()
    config["yara"]["feed_update_delay"] = seconds
    _save(config)

def toggle(status=None):
    """
    Turns background YARA scanning on or off, reverses the current setting if nothing is passed. Returns the new setting
    """
    config = _load()
    config["yara"]["enabled"] = (not config["yara"]["enabled"]) if status is None else status
    _save(config)
    return config["yara"]["enabled"]

# = Feeds

def list_feeds():
    return _load()["yara_feeds"]

def add_feed(index, name, url, description, local_path=None, level=None):
    """
    Adds a YARA rule feed. Without a url, local_path is a rule file of your own that's used as it is
    """
    config = _load()
    if index in config["yara_feeds"]:
        raise Exception(f"Error: YARA feed {index} already exists, the index must be unique")
    if not url and not local_path:
        raise Exception("A YARA feed needs a url to download, a local path to a rule file, or both")

    # Scans run from any directory, so a relative path would point somewhere else later
    config["yara_feeds"][index] = {
        "url": url or "",
        "name": name,
        "description": description,
        "local_path": os.path.abspath(os.path.expanduser(local_path or f"{FEED_DIR}/{index}.yar")),
        "last_refreshed": datetime(1970, 1, 1),
    }
    if level:  # Without one it's quick, in every scan level (utils.select_feeds)
        config["yara_feeds"][index]["level"] = level
    _save(config)

def remove_feed(index):
    config = _load()
    if index not in config["yara_feeds"]:
        raise Exception(f"YARA feed {index} not found in config")
    config["yara_feeds"].pop(index)
    _save(config)

def update_feed(index):
    """
    Downloads a feed's rule file, the whole file every time, replaced in one step
    """
    config = _load()
    try:
        feed = config["yara_feeds"][index]
    except KeyError:
        raise Exception(f"Error: YARA feed {index} does not exist")
    if not feed["url"]:
        return  # A local rule file, nothing to download

    path = os.path.expanduser(feed["local_path"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    utils.progress_download(feed["url"], path, skip_unchanged=True)

    config = _load()  # Re-read, the download can take a while
    config["yara_feeds"][index]["last_refreshed"] = datetime.now().replace(microsecond=0)
    _save(config)

def update_all_feeds():
    """
    Updates every feed, returns a list of the ones that failed (one failing doesn't stop the rest)
    """
    failures = []
    for index in list_feeds():
        try:
            update_feed(index)
        except Exception as e:
            failures.append(f"YARA feed {index}: {e}")
    return failures

# = Scanning

def _skipped(path):
    from menoa.utils.clam_utils import skipped_mounts
    return skipped_mounts(path) if os.path.isdir(path) else []

def _files(path, skip, onerror=None):
    if not os.path.isdir(path):
        yield path
        return
    for root, dirs, files in os.walk(path, onerror=onerror):  # Doesn't follow symlinks to directories
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in skip]
        for name in files:
            yield os.path.join(root, name)

def count_files(path):
    """
    How many results a scan of path will have, for progress bars
    """
    return sum(1 for _ in _files(path, _skipped(path)))

def _records(stream):
    # Records are "file\0result\0", so any file name works, even one with a newline in it
    fields, buffer = [], b""
    while chunk := stream.read1(1 << 16):
        *complete, buffer = (buffer + chunk).split(b"\0")
        fields += complete
        paired = len(fields) // 2 * 2
        for file, result in zip(fields[0:paired:2], fields[1:paired:2]):
            yield os.fsdecode(file), result.decode()
        fields = fields[paired:]

def scan_path_streaming(path, on_progress=None, on_summary=None, feeds=None, level=None):
    """
    Generator that scans path with every downloaded YARA feed, like clam_utils.scan_path_streaming()
    Yields (file, result) for every file ("OK", "YARA.<rule> FOUND", or why it was skipped or couldn't be read), (None, message) for problems with the scan
    on_progress(stage, 0, 0) is called while the rules compile, on_summary({"Scanned files", "YARA rules", "Time"}) at the end
    feeds and level pick which feeds to scan with, see utils.select_feeds(), every configured feed without them

    Raises an Exception if nothing could actually be checked (no rules, the scan crashed), so a failed scan is never mistaken for a clean one
    """

    if not os.path.exists(path):
        raise Exception(f"Path not found: {path}")

    rule_files = []
    for index, feed in utils.select_feeds(list_feeds(), feeds, level).items():
        feed_path = os.path.expanduser(feed["local_path"])
        if os.path.exists(feed_path):
            rule_files.append(feed_path)
        elif feeds:
            raise Exception(f"YARA feed {index} isn't downloaded, run `menoa yara reload {index}`")
        else:
            yield (None, f"YARA feed {index} skipped, {feed_path} doesn't exist (run `menoa yara reload {index}`)")
    if not rule_files:
        raise Exception("No YARA rules to scan with" + (f" at level {level}" if level else "") + ", add a feed with `menoa yara add` and run `menoa yara reload`")

    if on_progress:
        on_progress("Compiling YARA rules", 0, 0)
    start = time.monotonic()
    process = subprocess.Popen(
        # realpath: a symlink given directly is followed like clamscan does, the walk itself skips symlinks
        [sys.executable, "-m", "menoa.utils.yara_utils", os.path.realpath(path), *rule_files, *[f"--skip={d}" for d in _skipped(path)]],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    rules = scanned = 0

    try:
        for file, result in _records(process.stdout):
            if file == RULES_MARKER:
                rules = int(result)
                continue
            scanned += file != "" and (result == "OK" or result.endswith(" FOUND"))
            yield (file or None, result)
        process.wait()
    finally:
        # Stop YARA-X if the caller stops reading early
        if process.poll() is None:
            process.kill()
            process.wait()

    if process.returncode != 0:
        error = process.stderr.read().decode(errors="replace").strip().splitlines()
        raise Exception(f"YARA-X exited with code {process.returncode} before finishing: {error[-1] if error else 'no error output'}")
    if rules == 0:
        raise Exception("No YARA rules could be loaded, so nothing was scanned")

    if on_summary:
        on_summary({"Scanned files": str(scanned), "YARA rules": str(rules), "Time": f"{time.monotonic() - start:.3f} sec"})

def _main(args):
    import yara_x

    last_flush = time.monotonic()

    def send(file, result, flush=False):
        nonlocal last_flush
        sys.stdout.buffer.write(os.fsencode(file) + b"\0" + result.encode() + b"\0")
        # A few times a second, flushing for every file would slow big scans down
        if flush or time.monotonic() - last_flush > 0.1:
            sys.stdout.buffer.flush()
            last_flush = time.monotonic()

    path = args[0]
    skip = {a.split("=", 1)[1] for a in args[1:] if a.startswith("--skip=")}
    rule_files = [a for a in args[1:] if not a.startswith("--skip=")]

    compiler = yara_x.Compiler()
    compiler.ignore_invalid_rules(True)  # A rule YARA-X can't compile is left out instead of failing its whole file
    for i, rule_file in enumerate(rule_files):
        compiler.new_namespace(f"feed{i}")  # Two feeds can use the same rule name
        try:
            with open(rule_file, errors="replace") as f:
                compiler.add_source(f.read())
        except Exception as e:
            send("", f"YARA rules in {rule_file} skipped: {e}")
    rules = compiler.build()
    namespaces = [rule.namespace for rule in rules]
    send(RULES_MARKER, str(len(namespaces)), flush=True)
    for i, rule_file in enumerate(rule_files):
        # Like an HTML error page saved as a feed, otherwise scans would quietly run without it
        if f"feed{i}" not in namespaces:
            send("", f"No YARA rules could be loaded from {rule_file}")
    if not namespaces:
        return

    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(TIMEOUT)
    for file in _files(path, skip, onerror=lambda e: send(e.filename, "Can't open directory.")):
        try:
            info = os.lstat(file)
        except OSError as e:
            send(file, e.strerror)
            continue
        # Only regular files: opening a FIFO would hang, symlinked files are checked where they're stored
        if stat.S_ISLNK(info.st_mode):
            send(file, "Symbolic link")
        elif not stat.S_ISREG(info.st_mode):
            send(file, "Not a regular file")
        elif info.st_size == 0:
            send(file, "Empty file")
        elif info.st_size > MAX_FILE_SIZE:
            send(file, "Too big to scan")
        else:
            try:
                matches = [f"YARA.{rule.identifier}" for rule in scanner.scan_file(file).matching_rules]
                send(file, f"{', '.join(matches)} FOUND" if matches else "OK", flush=bool(matches))
            except yara_x.TimeoutError:
                send(file, f"YARA rules timed out after {TIMEOUT}s")
            except yara_x.ScanError as e:
                send(file, "Access denied" if "Permission denied" in str(e) else str(e).rsplit(": ", 1)[-1])
    sys.stdout.buffer.flush()

if __name__ == "__main__":
    _main(sys.argv[1:])
