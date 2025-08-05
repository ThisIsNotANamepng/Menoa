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
from utils.utils import alert

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
    return(str(threat_endpoints.get_endpoint_count())+" threats tracked")

def get_interface_summary():
    return "Interface Summary:\n - eth0: UP\n - wlan0: DOWN"

def get_realtime_logs():
    return (connections_check())

def reload_endpoints():
    # Reloads the enpoints by reading the csv file again
    print("Reloading...")

    threat_endpoints = []

    with open('../last30_days_active_urlhaus_enpoint.csv', mode='r', newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:

            # Srtip to just ip address
            ip = row['url']

            ip = ip.strip("http://").strip("https://")

            if "/" in ip:
                ip = ip[:ip.index("/")]

            if ip.count(".") == 3 and not any(c.isalpha() for c in ip):

                if ":" in ip:
                    ip = ip[:ip.index(":")]
                    
                threat_endpoints.append(ip)
    
    threat_endpoints = list(set(threat_endpoints))

    return threat_endpoints

def connections_check(verbose=True, desktop_notification=False):

    connections = psutil.net_connections(kind="inet")
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

            if desktop_notification: alert("Malicious endpoint detected", pid)
        
        
        if conn.raddr: display_conn_list += f"{conn.pid}: {conn.raddr.ip}:{conn.raddr.port}\n"

    return display_conn_list

threat_endpoints = ThreatEndpoints()