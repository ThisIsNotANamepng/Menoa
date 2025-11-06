"""
Compares hashes of local binaries to api provided known good ones
"""

import subprocess
import os
import json
import sqlite3
from pathlib import Path
import platform
import shutil
import time
import requests
import tomli, tomli_w

#from utils.utils import alert

DB_PATH = str(Path.home())+"/.menoa/attestation.db"

def get_number_of_binaries():
    """
    Returns the total number of binaries in the database
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM attestation")
    except sqlite3.OperationalError:
        create_table()
        cursor.execute("SELECT COUNT(*) FROM attestation")
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_binary_data():
    """
    Returns a list of tuples containing all data form the database
    """

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT path, version, hash, validated FROM attestation")
    rows = cursor.fetchall()
    conn.close()

    # Convert database rows to display format
    binary_data = []
    for path, version, hash_val, validated in rows:

        status = convert_validation_status(validated)

        binary_data.append((path, version, hash_val, status))

    return binary_data


def convert_validation_status(validated):
    """
    Converts database numeric validation status to human-friendly string
    """
    status_map = {
        1: "Validated",
        0: "Pending",
        -1: "Tampered!",
        2: "Legacy/Not Checkable"
    }

    return status_map.get(validated, "Unknown")

def get_sha256_hash(input_string):
    # Get the hash of a binary
    
    file_path = f"/bin/{input_string}"

    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return None

    try:
        result = subprocess.run(['sha256sum', file_path], capture_output=True, text=True, check=True)
        hash_value = result.stdout.split()[0]  # The hash is the first part of the output
        return hash_value
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while running sha256sum: {e}")
        return None

def attest_with_server(json):
    # Send json to server and finds the status for sent binaries

    response = requests.post("https://api.endpoint.org/batch", json={"files": data})

def detect_package_manager():
    """
    Detect the package manager available on the system.
    Returns: Tuple(package_manager_name, version_check_template)
    """
    package_managers = {
        'apt': 'apt show {pkg}',
        'dnf': 'dnf info {pkg}',
        'yum': 'yum info {pkg}',
        'pacman': 'pacman -Qo {pkg}',
        'zypper': 'zypper info {pkg}',
        'apk': 'apk info {pkg}',
        'emerge': 'equery list {pkg}'
    }

    for manager, command_template in package_managers.items():
        if shutil.which(manager):
            return manager, command_template

    return None, None

def get_package_version(package_path):
    """
    Detects distro and package manager, and returns the command to get package version.
    """
    manager, command_template = detect_package_manager()

    if manager and command_template:
        version_command = command_template.format(pkg=package_path)
    else:
        return {
            'package_manager': 'unknown',
            'command': 'Package manager not found.'
        }

    
    pkg_result = subprocess.run(version_command.split(), capture_output=True, text=True)

    if manager == "pacman":
        if pkg_result.returncode != 0:
            print("Error finding package:", pkg_result.stderr)
        else:
            # Extract package name from output
            # Example output: "/bin/ls is owned by coreutils 9.4-1"
            line = pkg_result.stdout.strip()
            parts = line.split()
            if len(parts) >= 5:
                pkg_name = parts[4]
                
                # Step 2: Get package info
                info_result = subprocess.run(['pacman', '-Qi', pkg_name], capture_output=True, text=True)
                if info_result.returncode == 0:
                    version = info_result.stdout.split("\n")[1].split()[2]

                    return version
                else:
                    print("Error getting package info:", info_result.stderr)
            else:
                print("Unexpected output format:", line)
    

def update_database():
    # Compares data in local database and binaries

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    query = "SELECT path, hash, version FROM attestation"

    try:
        cursor.execute(query)
        rows = cursor.fetchall()


        for row in rows:
            path, hash_value, version = row

            if get_sha256_hash(path) != hash_value:
                # Hashes are different for the hash in the database and the real one, check for different version, if different then update the package, if not, notify a tampered binary

                if version == get_package_version(path):
                    # Binary has been tampered with
                    print(path, "has been tampered with")

                    ## TODO: Add logic here to deal with tampered binaries

                else:
                    # Update binary version and hash in database

                    delete_binary(path)
                    insert_binary(path, time.time(), get_package_version(path), get_sha256_hash(path))

        db_paths = []

        for i in rows:
            db_paths.append(i[0])

        system_paths = os.listdir("/bin")

        # Sort through all binaries in the db and in the system for packages that have been recently installed or deleted

        for path in db_paths:
            if path not in system_paths:
                # Package has been deleted
                delete_binary(path)

        for path in system_paths:
            if path not in db_paths:
                # Package has been installed
                insert_binary(path, time.time(), get_package_version(path), get_sha256_hash(path))

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        cursor.close()
        connection.close()

def attestation():
    # Returns all binaries with hashes

    files = os.listdir("/bin")
    data = []

    for file_name in files:
        file_path = os.path.join("/bin/", file_name)
        if os.path.isfile(file_path):
            hash_value = get_sha256_hash(file_name)
            file_path = file_path[5:]

            data.append({
                file_path: hash_value
            })
    
    return data

def attest():
    """
    Validate binaries with the server

    Refreshes the database, then sends the data in the database to the api
    """

    update_database()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''SELECT path,version,hash FROM attestation WHERE validated != 1''')
    
    results = cursor.fetchall()
    conn.close()

    print(results)

    #print(results)
    response = requests.post(
        'http://localhost:5000/v1/signatures',
        json=[list(pkg) for pkg in results]
    )

    print(len(results))
    installed_packages = [row[0] for row in results]
    
    for package, status in response.json().items():
        #print(package, status)
        if package in installed_packages:
            installed_packages.remove(package)

        else:
            if status == "upgrading":
                # Mark package validated as 0, to be validated later
                set_validation(package, 0)
            elif status == "not_in_database":
                # Mark as 2, not in database and never will be
                set_validation(package, 2)
            elif status == "tampered":
                # Mark package as -1 and alert as tampered
                set_validation(package, -1)
                #alert("Found Compromised Binary", f"{package} has a compromised signature") ##TODO Add this when importing utils works


    for package in installed_packages:
        # Package has been validated by api
        set_validation(package, 1)

def register():
    # Registers binaries, hashes, and versions in the local database

    binaries = attestation()

    for dict_index, d in enumerate(binaries):
        for name, hash in d.items():

            print(name, hash, get_package_version(name))
            insert_binary(name, time.time(), get_package_version("/bin/"+name), hash)


def create_table():
    """
    Creates an SQLite3 database with a table 'attestation' containing
    columns 'path', 'date_checked', 'version', and 'hash' (all as TEXT).
    """
    print("Creating attestation database...")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attestation (
            path TEXT,
            date_checked TEXT,
            version TEXT,
            hash TEXT,
            validated NUMERIC
        )
    ''')

    conn.commit()
    conn.close()
    
def insert_binary(path, date_checked, version, hash_value):
    """
    Inserts a row into the 'attestation' table.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO attestation (path, date_checked, version, hash, validated)
        VALUES (?, ?, ?, ?, ?)
    ''', (path, date_checked, version, hash_value, 0))
    
    conn.commit()
    conn.close()

def delete_binary(path):
    """
    Deletes a binary from the db given the path
    """

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        DELETE FROM attestation
        WHERE path = ?
    ''', (path))
    
    conn.commit()
    conn.close()

def set_validation(package, status):
    """
    Mark the validation status of a package in the database
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("UPDATE attestation SET validated = ? WHERE path = ?", (status, package))
    
    conn.commit()
    conn.close()

def toggle(status=None):
    """
    Toggles attestation, reverses current status if nothing is passed
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    current = config["attestation"]["enabled"]

    if status is None:
        config["attestation"]["enabled"] = not current
    else:
        config["attestation"]["enabled"] = status

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

    if status is None: return not current
    else: return status

def set_scanning_delay(seconds):
    """
    Sets the delay for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["attestation"]["scan_delay"] = seconds

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

def get_scanning_delay():
    """
    Returns the delay for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["attestation"]["scan_delay"]

def toggle(status=None):
    """
    Toggles scanning, reverses current status if nothing is passed
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    current = config["attestation"]["enabled"]

    if status is None:
        config["attestation"]["enabled"] = not current
    else:
        config["attestation"]["enabled"] = status

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

    if status is None: return not current
    else: return status
