"""
Compares hashes of local binaries to api provided known good ones
"""

import subprocess
import os
import json
import sqlite3

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

def attestation():
    # Main funtion, reads binaries and sends to server

    files = os.listdir("/bin")
    data = []

    for file_name in files:
        file_path = os.path.join("/bin", file_name)
        if os.path.isfile(file_path):
            hash_value = get_sha256_hash(file_name)
            file_path = file_path[5:]

            data.append({
                file_path: hash_value
            })

    json_payload = json.dumps({"files": data})
    print(json_payload)

    f=open("output.txt", "w")
    f.write(json_payload)
    f.close()

def get_binary_data():
    # Returns a list of tuples, each tuple has the binary path, version, hash, and whether it's been checked with the api

    return ([("name", "version", "hash", "checked"), ("name", "version", "hash", "checked")])

def get_number_of_binaries():
    # Returns the number of binaries currently in use. Searches the database for the lastest version of all binaries
    ## Need to connect the datatbase to the binaries actually on the system, needs some signal or clock to periodically check for new or updated binaries for inclusin in the database

    return 2


def create_table(db_name):
    """
    Creates an SQLite3 database with a table 'attestation' containing
    columns 'path', 'date_checked', 'version', and 'hash' (all as TEXT).
    
    Parameters:
        db_name (str): The name of the database file to create (e.g., 'attestation.db').
    """
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attestation (
            path TEXT,
            date_checked TEXT,
            version TEXT,
            hash TEXT
        )
    ''')

    conn.commit()
    conn.close()
    
def insert_binary(db_name, path, date_checked, version, hash_value):
    """
    Inserts a row into the 'attestation' table.
    """
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO attestation (path, date_checked, version, hash)
        VALUES (?, ?, ?, ?)
    ''', (path, date_checked, version, hash_value))
    
    conn.commit()
    conn.close()

def get_attestation(db_name, path, version):
    """
    Retrieves all rows from 'attestation' table that match the given path and version.
    """
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM attestation
        WHERE path = ? AND version = ?
    ''', (path, version))
    
    results = cursor.fetchall()
    conn.close()
    return results

def delete_older_versions(db_name, path, min_version):
    """
    Deletes rows from 'attestation' table for the given path where version is less than min_version.
    Note: Version comparison is done lexicographically.
    """
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute('''
        DELETE FROM attestation
        WHERE path = ? AND version < ?
    ''', (path, min_version))
    
    conn.commit()
    conn.close()
