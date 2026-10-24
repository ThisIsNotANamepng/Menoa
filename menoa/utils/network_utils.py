"""
Handles backend for network connection monitoring

TODO:
    - Nothing happens when a threat is detected, it just prints a message
    - Need to fetch the list from a server to refresh feed
    - Need to add ability to add custom threat feeds
    - Need a clock to actually check the connections for threats
    - The conn display list is updated with connections_check(), when there's a clock for running clock() it will be running twice haphazardly
"""

import psutil, csv, time
import menoa.utils.utils as utils
from pathlib import Path
import tomli, tomli_w
import io, os, re, shlex, subprocess, ipaddress
from datetime import datetime
from urllib.parse import urlparse
import requests

FEED_FORMATS = ("plain", "csv", "misp", "command")

class ThreatEndpoints:
    def __init__(self):
        self.endpoints = reload_endpoints()

    def reload(self, item):
        """Reload the list"""
        self.endpoints = reload_endpoints()

    def get_endpoints(self):
        """Return the current list of endpoints."""
        return self.endpoints

    def get_endpoint_count(self):
        """Returns the number of endpoints currently tracked"""
        return len(self.endpoints)

def number_of_threats():
    threat_endpoints = ThreatEndpoints()
    return(str(threat_endpoints.get_endpoint_count())+" Threats Tracked")

def get_interface_summary():
    return "Interface Summary:\n - eth0: UP\n - wlan0: DOWN"

def feed_cache_path(index):
    # Every feed, whatever its format, is stored locally as one normalized IP per line
    return Path.home() / ".menoa" / "feeds" / "network" / f"{index}.txt"

def get_number_of_threats_from_feed(index):
    # Returns the number of IPs stored for a feed, or None if it hasn't been downloaded

    path = feed_cache_path(index)
    if not path.exists():
        return None

    with open(path, "r") as f:
        return sum(1 for line in f if line.strip())

def get_feed_summary():
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    summary = "\n\nNetwork Feeds Summary:\n"

    for i in config["network_feeds"]:
        count = get_number_of_threats_from_feed(i)
        summary += f" - {i}: " + ("not downloaded" if count is None else f"{count} threats") + "\n"

    return summary

def get_realtime_logs():
    return (connections_check())

def update_all_feeds():
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

def read_source(url, stored_file=None):
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

def fetch_feed_values(feed, stored_file=None):
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

def normalize_indicators(values):
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

def update_feed(index):
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

def reload_endpoints():
    # Returns a set of the IPs from all downloaded network feeds

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    threat_endpoints = set()

    for i in config["network_feeds"]:
        path = feed_cache_path(i)
        if not path.exists():
            print(f"Network feed {i} hasn't been downloaded yet, run `menoa network reload {i}`")
            continue

        with open(path, "r") as f:
            threat_endpoints.update(line.strip() for line in f if line.strip())

    return threat_endpoints

def connections_check(verbose=True, desktop_notification=False):

    connections = psutil.net_connections(kind="inet")
    threat_endpoints = ThreatEndpoints()
    endpoints = threat_endpoints.get_endpoints()

    display_conn_list = ""

    for conn in connections:
        # Go through connections, check each one to see if it's in the threat list

        # Dual-stack sockets report IPv4 peers as ::ffff:1.2.3.4
        remote_ip = conn.raddr.ip.removeprefix("::ffff:") if conn.raddr else None

        if remote_ip in endpoints:
            pid = conn.pid

            if verbose:
                print(f"Match found: Remote IP {conn.raddr.ip}:{conn.raddr.port}")
                print(f"Local Address: {conn.laddr.ip}:{conn.laddr.port}")
                print(f"Status: {conn.status}")
            if pid:
                try:
                    proc = psutil.Process(pid)
                    if verbose:
                        print(f"PID: {pid}")
                        print(f"Command: {' '.join(proc.cmdline())}")
                        print(f"Executable: {proc.exe()}")
                        print(f"Username: {proc.username()}")
                except psutil.NoSuchProcess:
                    if verbose:
                        print(f"Process {pid} no longer exists.")
            else:
                if verbose:
                    print("No PID associated with this connection.")
            if verbose: print("-" * 60)

            if desktop_notification: utils.alert("Malicious endpoint detected", pid)
        
        
        if conn.raddr: display_conn_list += f"{conn.pid}: {conn.raddr.ip}:{conn.raddr.port}\n"

    return display_conn_list

def add_feed(index, name, description, format, url=None, column=None, command=None, api_key_env=None):
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

def remove_feed(index):
    """
    Removes a network feed from the config
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    if index not in config["network_feeds"].keys():
        raise Exception("Given feed index not found in config")

    config["network_feeds"].pop(index)

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

    feed_cache_path(index).unlink(missing_ok=True)

def list_feeds():
    """
    Returns a dictionary with all of the network feeds
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["network_feeds"]

def get_delay():
    """
    Returns the delay for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["network"]

def set_scanning_delay(seconds):
    """
    Sets the delay for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["network"]["scan_delay"] = seconds

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)


def set_feed_update_delay(seconds):
    """
    Sets the delay for refresh
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["network"]["feed_update_delay"] = seconds

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)
        
def toggle(status=None):
    """
    Toggles scanning, reverses current status if nothing is passed
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

#threat_endpoints = ThreatEndpoints()