import subprocess
import shutil
import os
from typing import List, Tuple, Optional


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


def parse_clamscan_output(output: str) -> List[Tuple[str, str]]:
    """
    Parses clamscan output and returns list of (file, result) tuples.
    Example:
        /path/to/file.txt: OK
        /path/to/infected.exe: Eicar-Test-Signature FOUND
    """
    parsed_results = []
    for line in output.strip().splitlines():
        if not line or line.startswith("-----------") or line.startswith("SCAN SUMMARY"):
            continue

        if ": " in line:
            path, result = line.rsplit(": ", 1)
            parsed_results.append((path.strip(), result.strip()))
    return parsed_results


def get_scan_summary(results: List[Tuple[str, str]]) -> dict:
    """Takes parsed results and returns a summary dict."""
    summary = {
        "scanned": len(results),
        "infected": 0,
        "clean": 0,
        "errors": 0
    }
    for _, result in results:
        if result == "OK":
            summary["clean"] += 1
        elif result.endswith("FOUND"):
            summary["infected"] += 1
        else:
            summary["errors"] += 1
    return summary


def scan_path_streaming(path: str, recursive: bool = True):
    """
    Generator that streams clamscan output line-by-line.
    Yields (filename, result) as they're found.
    """
    if not is_clamscan_available():
        yield ("ERROR", "clamscan not found in PATH.")
        return

    if not os.path.exists(path):
        yield ("ERROR", f"Path not found: {path}")
        return

    cmd = ["clamscan"]
    if recursive:
        cmd.append("-r")
    cmd.append(path)

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
