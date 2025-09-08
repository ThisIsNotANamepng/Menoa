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
import shutil

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

def get_number_of_threats_from_feed(filepath):
    # Takes a threat feed csv and returns the number of threats tracked in it

    filepath = filepath.replace("~", str(Path.home()))
    with open(filepath, "r") as f:
        count = 0
        for line in f:
            count += 1

    return count

def get_feed_summary():
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    summary = "\n\nNetwork Feeds Summary:\n"

    print()
    for i in config["network_feeds"]:
        summary += " - "+i
        #summary += " - "+str(config["network_feeds"][i]["last_refreshed"])+"\n"
        summary += ": "+str(get_number_of_threats_from_feed(config["network_feeds"][i]["local_path"]))+" threats"+"\n"

    return summary

def get_realtime_logs():
    return (connections_check())

def update_all_feeds():
    with open(str(Path.home())+"/.menoa/config.toml", "r") as file:
        config = file.read()

    toml_dict = tomli.loads(config)

    for i in toml_dict['network_feeds'].keys():
        update_feed(i)

def update_feed(index):
    """
    Updates a feed using the given index
    """

    with open(str(Path.home())+"/.menoa/config.toml", "r") as file:
        config = file.read()

    toml_dict = tomli.loads(config)

    try:
        feed = (toml_dict["network_feeds"][index])
    except KeyError:
        raise Exception("Error: Feed does not exist")

    if feed["supports_versioning"]:
        utils.progress_patch_download(feed['url'], feed["local_path"].replace("~", str(Path.home())), feed["current_version"])
    else:
        utils.progress_download(feed['url'], feed["local_path"].replace("~", str(Path.home())))

def reload_endpoints():
    # Returns a list of the endpoints retreived from network feeds
    #print("Reloading...")

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    paths = []

    for i in config["network_feeds"]:
        paths.append(config["network_feeds"][i]["local_path"])

    threat_endpoints = []

    for i in paths:
        i = i.replace("~", str(Path.home()))
        try:
            with open(i, mode='r', newline='') as file:
                reader = csv.DictReader(file)
                for row in reader:

                    # Strip to just ip address
                    ip = row['url']

                    ip = ip.strip("http://").strip("https://")

                    if "/" in ip:
                        ip = ip[:ip.index("/")]

                    if ip.count(".") == 3 and not any(c.isalpha() for c in ip):

                        if ":" in ip:
                            ip = ip[:ip.index(":")]
                            
                        threat_endpoints.append(ip)
        except FileNotFoundError:
            raise Exception(f"Your feed config references a local path ({i}) which doesn't exist")
    
    threat_endpoints = list(set(threat_endpoints))

    return threat_endpoints

def connections_check(verbose=True, desktop_notification=False):

    connections = psutil.net_connections(kind="inet")
    threat_endpoints = ThreatEndpoints()
    endpoints = threat_endpoints.get_endpoints()

    display_conn_list = ""

    for conn in connections:
        #print(conn)
        # Go through connections, check each one to see if it's in the threat list

        if conn.raddr and conn.raddr.ip in endpoints:
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

def add_feed(index, name, url, description, local_path, supports_versioning=False, move_into_default_feed_path=True):
    """
    Adds a network feed from the config
    if `move_into_default_feed_path` is True Menoa will try to copy the given filepath into `~/.menoa/feeds/network/xxxx``
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    if index in config["network_feeds"].keys():
        raise Exception("Error: Feed with index", index, "already exists. This identifier must be unique")

    if move_into_default_feed_path: # Copy filepath into local feed storage
        new_path = str(Path.home())+"/.menoa/feeds/network/"+Path(local_path).name
        shutil.copy2(local_path, new_path)
        local_path = new_path

    config["network_feeds"][index] = {
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
    Removes a network feed from the config
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    if index not in config["network_feeds"].keys():
        raise Exception("Given feed index not found in config")

    config["network_feeds"].pop(index)

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

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