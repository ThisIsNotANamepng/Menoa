import subprocess
import shutil
import os
from typing import List, Tuple, Optional
from datetime import datetime

def is_clamscan_available() -> bool:
    """Check if clamscan is installed and available in PATH."""
    return shutil.which("clamscan") is not None

def is_freshclam_available() -> bool:
    """Check if freshclam (database updater) is installed."""
    return shutil.which("freshclam") is not None

def update_virus_database() -> Tuple[bool, str]:
    """Run freshclam to update the virus database."""
    if not is_freshclam_available():
        return False, "freshclam not found in PATH."

    try:
        result = subprocess.run(["sudo", "freshclam"], capture_output=True, text=True, check=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stdout + "\n" + e.stderr

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

def scan_path_streaming(path: str, recursive: bool = True):
    """
    Generator that streams clamscan output line-by-line.
    Yields (filename, result) as they're found.
    """
    if not is_clamscan_available():
        print("Clam error")
        yield ("ERROR", "clamscan not found in PATH.")
        return

    if not os.path.exists(path):
        print("path error")
        yield ("ERROR", f"Path not found: {path}")
        return

    cmd = ["clamscan"]

    if recursive:
        cmd.append("-r")
    cmd.append(path)

    print(path)

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    for line in process.stdout:
        if ": " in line:
            file, result = line.strip().rsplit(": ", 1)
            yield (file, result)

def get_clamav_version() -> Optional[str]:
    """Return the version of clamscan if available."""
    if not is_clamscan_available():
        return None

    try:
        result = subprocess.run(["clamscan", "-V"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

def get_database_version():
    # Returns the database patch version and when it was last changed

    full = get_clamav_version().split("/")

    return (full[1], full[2])

def get_last_time_scanned():
    # Returns the last time the system was scanned, found in /gui/data/last_scanned

    last_scanned = ""

    with open("data/last_scanned", "r") as file:
        last_scanned = file.read()

    return last_scanned

def set_last_time_scanned():
    # Updates the last time the system was scanned, found in /gui/data/last_scanned

    with open("data/last_scanned", "w") as file:
        file.write(datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"))

def get_scan_total(path):
    total = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.is_file():
                    total += 1
                elif entry.is_dir(follow_symlinks=False):
                    total += get_scan_total(entry.path)
    except PermissionError:
        pass  # Skip folders/files we can't access
    return total
    

#for file, result in scan_path_streaming("/home/jack/Downloads"):
#    print(file, result)