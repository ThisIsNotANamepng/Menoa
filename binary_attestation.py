"""
Compares hashes of local binaries to api provided known good ones
"""

import subprocess
import os
import json

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
