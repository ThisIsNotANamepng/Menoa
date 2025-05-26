import psutil, csv, time


def reload_endpoints(threat_endpoints):
    # Reloads the enpoints by reading the csv file again

    threat_endpoints = []

    with open('last30_days_active_urlhaus_enpoint.csv', mode='r', newline='') as file:
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

def main():
    # List of IPs to check against

    threat_endpoints = []
    threat_endpoints = reload_endpoints(threat_endpoints)
    connections = psutil.net_connections(kind="inet")

    for conn in connections:
        #print(conn)
        # Go through connections, check each one to see if it's in threat_enpoints

        if conn.raddr and conn.raddr.ip in threat_endpoints:
            pid = conn.pid
            print(f"Match found: Remote IP {conn.raddr.ip}:{conn.raddr.port}")
            print(f"Local Address: {conn.laddr.ip}:{conn.laddr.port}")
            print(f"Status: {conn.status}")
            if pid:
                try:
                    proc = psutil.Process(pid)
                    print(f"PID: {pid}")
                    print(f"Command: {' '.join(proc.cmdline())}")
                    print(f"Executable: {proc.exe()}")
                    print(f"Username: {proc.username()}")
                except psutil.NoSuchProcess:
                    print(f"Process {pid} no longer exists.")
            else:
                print("No PID associated with this connection.")
            print("-" * 60)

if __name__ == "__main__":
    start=time.time()
    main()
    print(time.time()-start)
