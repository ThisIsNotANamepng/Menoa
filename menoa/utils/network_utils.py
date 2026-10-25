"""
Handles backend for network connection monitoring
Connections are only checked by `menoa network scan` or while the Network page is open, until the background clock exists (README)
"""

import psutil, csv
import menoa.utils.utils as utils
from pathlib import Path
import tomli, tomli_w
import os, re, shlex, socket, subprocess, ipaddress
from datetime import datetime
from urllib.parse import urlparse
import requests
from typing import Any, Dict, Iterable, List, Optional, Set

FEED_FORMATS = ("plain", "csv", "misp", "command")

def number_of_threats() -> str:
    """
    Returns how many IPs the downloaded feeds have, like "5 Threats Tracked"
    """
    return f"{len(reload_endpoints())} Threats Tracked"

def get_interface_summary() -> str:
    """
    Returns the machine's network interfaces, whether they're up, and their IPv4 addresses, as text
    """
    addresses = psutil.net_if_addrs()
    summary = "Interface Summary:"
    for name, stats in sorted(psutil.net_if_stats().items()):
        if name == "lo":
            continue
        ips = [a.address for a in addresses.get(name, []) if a.family == socket.AF_INET]
        summary += f"\n - {name}: {'UP' if stats.isup else 'DOWN'}" + (f" {', '.join(ips)}" if ips else "")
    return summary

def feed_cache_path(index: str) -> Path:
    """
    Where a feed's IPs are stored. Every feed, whatever its format, is stored locally as one normalized IP per line
    """
    return Path.home() / ".menoa" / "feeds" / "network" / f"{index}.txt"

def get_number_of_threats_from_feed(index: str) -> Optional[int]:
    """
    Returns the number of IPs stored for a feed, or None if it hasn't been downloaded
    """
    path = feed_cache_path(index)
    if not path.exists():
        return None

    with open(path, "r") as f:
        return sum(1 for line in f if line.strip())

def get_feed_summary() -> str:
    """
    Returns each network feed and how many IPs it has, as text
    """
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    summary = "\n\nNetwork Feeds Summary:\n"

    for i in config["network_feeds"]:
        count = get_number_of_threats_from_feed(i)
        summary += f" - {i}: " + ("not downloaded" if count is None else f"{count} threats") + "\n"

    return summary

def update_all_feeds() -> List[str]:
    """
    Downloads every network feed, returns a list of the ones that failed (one failing doesn't stop the rest)
    """
    with open(str(Path.home())+"/.menoa/config.toml", "r") as file:
        config = file.read()

    toml_dict = tomli.loads(config)

    # One broken feed shouldn't stop the others from updating, returns the ones that failed
    failures = []
    for i in toml_dict['network_feeds'].keys():
        try:
            print(f"{i}: {update_feed(i)} IPs")
        except Exception as e:
            print(f"Failed to update {i}, keeping previous data: {e}")
            failures.append(f"{i}: {e}")

    return failures

def read_source(url: str, stored_file: Optional[Path] = None) -> Optional[str]:
    """
    Returns the text at a url, or at a local path ("/..." or "file://...")
    With stored_file, returns None if the server says the url hasn't changed since it was last saved there
    """

    if url.startswith("file://"):
        url = url[len("file://"):]
    if url.startswith("/"):
        with open(url, "r") as f:
            return f.read()

    r = requests.get(url, timeout=60, headers=utils.cached_headers(stored_file, url) if stored_file else {})
    if r.status_code == 304:
        return None
    r.raise_for_status()
    if stored_file:
        # The caller stores it next, update_feed forgets these if that fails
        utils.save_validators(stored_file, url, r)
    return r.text

def fetch_feed_values(feed: Dict[str, Any], stored_file: Optional[Path] = None) -> Optional[List[str]]:
    """
    Downloads a feed and returns its raw values (one candidate indicator per item), or None if a plain/csv file hasn't changed
    since it was saved to stored_file. Based on feed["format"]:

    - plain: one indicator per line, "#" starts a comment
    - csv: the value in `column`, a header name or a 0-based column number
    - misp: ip-src/ip-dst attributes from a MISP server's restSearch, using the API key in the env var `api_key_env`
    - command: one indicator per line printed by `command`
    """

    fmt = feed.get("format")

    if fmt == "plain":
        text = read_source(feed["url"], stored_file)
        return None if text is None else text.splitlines()

    if fmt == "csv":
        text = read_source(feed["url"], stored_file)
        if text is None:
            return None
        lines = [l for l in text.splitlines() if not l.startswith("#")]
        column = feed["column"]
        if isinstance(column, int):
            return [row[column] for row in csv.reader(lines) if len(row) > column]
        return [row.get(column) or "" for row in csv.DictReader(lines)]

    if fmt == "misp":
        key = os.environ.get(feed["api_key_env"])
        if not key:
            raise Exception(f"Set the {feed['api_key_env']} environment variable to your MISP API key")

        r = requests.post(
            feed["url"].rstrip("/") + "/attributes/restSearch",
            headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
            # enforceWarninglist drops known-benign IPs (public DNS, CDNs) that would cause false alarms
            json={"returnFormat": "text", "type": ["ip-src", "ip-dst"], "to_ids": True, "enforceWarninglist": True},
            timeout=120,
        )
        r.raise_for_status()
        return r.text.splitlines()

    if fmt == "command":
        result = subprocess.run(shlex.split(feed["command"]), capture_output=True, text=True, check=True, timeout=300)
        return result.stdout.splitlines()

    raise Exception(f"Unknown feed format {fmt!r}, must be one of {', '.join(FEED_FORMATS)}")

def normalize_indicators(values: Iterable[str]) -> Set[str]:
    """
    Turns raw feed values into a set of IP strings. Feeds are untrusted input, so anything that isn't an IP is dropped
    Accepts bare IPs and URLs with an IP host ("http://1.2.3.4:8080/x"), text after the first space or "#" is ignored
    """

    ips = set()

    for value in values:
        value = value.split("#")[0].strip()
        if not value:
            continue
        value = value.split()[0]

        host = urlparse(value).hostname if "://" in value else value
        try:
            ip = ipaddress.ip_address(host)
        except (ValueError, TypeError):
            continue

        # These would match local traffic on every machine, flagging everything
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
            continue

        ips.add(str(ip))

    return ips

def update_feed(index: str) -> Optional[int]:
    """
    Downloads a feed using the given index, stores its IPs in the feed's cache file, and returns how many were found
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    try:
        feed = config["network_feeds"][index]
    except KeyError:
        raise Exception("Error: Feed does not exist")

    path = feed_cache_path(index)
    try:
        values = fetch_feed_values(feed, path)
        if values is None:
            count = get_number_of_threats_from_feed(index)  # Unchanged upstream, the stored IPs are current
        else:
            ips = normalize_indicators(values)

            # An empty result is almost always a misconfigured feed, don't wipe the good data from last time
            if not ips:
                raise Exception(f"No valid IPs found in {index}, keeping previous data")

            # Write then rename so a crash mid-write can't leave a truncated feed
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text("\n".join(sorted(ips)) + "\n")
            os.replace(tmp, path)
            count = len(ips)
    except Exception:
        # So the next refresh downloads the feed in full instead of trusting a copy that wasn't stored
        utils.forget_validators(path)
        raise

    config["network_feeds"][index]["last_refreshed"] = datetime.now().replace(microsecond=0)
    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

    return count

def reload_endpoints() -> Set[str]:
    """
    Returns a set of the IPs from all downloaded network feeds
    """
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    threat_endpoints = set()

    for i in config["network_feeds"]:
        path = feed_cache_path(i)
        if path.exists():  # See missing_feeds()
            with open(path, "r") as f:
                threat_endpoints.update(line.strip() for line in f if line.strip())

    return threat_endpoints

def missing_feeds() -> List[str]:
    """
    Returns the network feeds in the config that haven't been downloaded, so connections aren't checked against them
    """
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)
    return [i for i in config.get("network_feeds", {}) if not feed_cache_path(i).exists()]

def connections_check(desktop_notification: bool = False) -> List[Dict[str, Any]]:
    """
    Checks the current connections against the downloaded network feeds. Returns one dict per connection with a remote address,
    {"pid", "process", "remote", "malicious"}, malicious ones first. Raises if no feed is downloaded, since nothing could be checked
    """
    endpoints = reload_endpoints()
    if not endpoints:
        raise Exception("No network feeds are downloaded, so connections can't be checked (run `menoa network reload`)")

    results = []
    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue

        # Dual-stack sockets report IPv4 peers as ::ffff:1.2.3.4
        ip = conn.raddr.ip.removeprefix("::ffff:")
        process = ""
        if conn.pid:  # None for other users' processes unless Menoa runs as root
            try:
                process = psutil.Process(conn.pid).name()
            except psutil.Error:
                pass

        results.append({
            "pid": conn.pid,
            "process": process,
            "remote": f"[{ip}]:{conn.raddr.port}" if ":" in ip else f"{ip}:{conn.raddr.port}",
            "malicious": ip in endpoints,
        })

    results.sort(key=lambda r: not r["malicious"])

    if desktop_notification:
        for r in results:
            if r["malicious"]:
                utils.alert("Malicious endpoint detected", f"{r['process'] or 'A process'} (PID {r['pid'] or 'unknown'}) is connected to {r['remote']}")

    return results

def add_feed(index: str, name: str, description: str, format: str, url: Optional[str] = None, column: Optional[Any] = None,
             command: Optional[str] = None, api_key_env: Optional[str] = None) -> None:
    """
    Adds a network feed to the config, see fetch_feed_values() for what each format needs
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    # The index is used as the cache filename
    if not re.fullmatch(r"[\w-]+", index):
        raise Exception("Feed index can only contain letters, numbers, _ and -")

    if index in config["network_feeds"].keys():
        raise Exception(f"Error: Feed with index {index} already exists. This identifier must be unique")

    if format not in FEED_FORMATS:
        raise Exception(f"Unknown feed format {format!r}, must be one of {', '.join(FEED_FORMATS)}")

    required = {"plain": ["url"], "csv": ["url", "column"], "misp": ["url", "api_key_env"], "command": ["command"]}[format]
    fields = {"url": url, "column": column, "command": command, "api_key_env": api_key_env}
    missing = [f for f in required if fields[f] is None]
    if missing:
        raise Exception(f"A {format} feed needs: {', '.join(missing)}")

    feed = {"name": name, "description": description, "format": format, "last_refreshed": datetime(1970, 1, 1)}
    for f in required:
        feed[f] = fields[f]

    config["network_feeds"][index] = feed

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

def remove_feed(index: str) -> None:
    """
    Removes a network feed from the config, and its stored IPs
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    if index not in config["network_feeds"].keys():
        raise Exception("Given feed index not found in config")

    config["network_feeds"].pop(index)

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

    feed_cache_path(index).unlink(missing_ok=True)

def list_feeds() -> Dict[str, Dict[str, Any]]:
    """
    Returns every network feed in the config, {index: feed}
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["network_feeds"]

def get_delay() -> Dict[str, Any]:
    """
    Returns the [network] settings: scan_delay, feed_update_delay and enabled
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["network"]

def set_scanning_delay(seconds: float) -> None:
    """
    Sets how many seconds background checks wait between runs
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["network"]["scan_delay"] = seconds

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)


def set_feed_update_delay(seconds: float) -> None:
    """
    Sets how many seconds to wait between feed updates
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["network"]["feed_update_delay"] = seconds

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)
        
def toggle(status: Optional[bool] = None) -> bool:
    """
    Turns background checks on or off, reverses the current setting if nothing is passed. Returns the new setting
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    current = config["network"]["enabled"]

    if status is None:
        config["network"]["enabled"] = not current
    else:
        config["network"]["enabled"] = status

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

    if status is None: return not current
    else: return status
