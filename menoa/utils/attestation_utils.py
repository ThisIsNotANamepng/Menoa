"""
Compares hashes of local binaries to api provided known good ones

The attestation server doesn't return verdicts, it returns the expected sha256 of each binary, signed with Menoa's private key.
Those signed hashes are kept in a local database, so each binary is only sent to the server once per package version, and every
later check is a local comparison. Malware that edits the database can't forge a signature, so the worst it can do is make
binaries show as Pending or "Record tampered!", never Validated.

Server API (POST {server_url}/v1/attest):
    request:  {"distro": "ubuntu 25.10", "arch": "x86_64", "binaries": [{"path": "/usr/bin/ls", "package": "coreutils", "version": "9.5-1"}]}
    response: {"records": {"/usr/bin/ls": {"sha256": "<hex>", "signature": "<base64 Ed25519 signature>"}}}
A binary missing from "records" is unknown to the server (e.g. a version it hasn't indexed yet), it stays Pending and is asked again
next time. The signature covers signed_message(), a newline-joined string, so a server in any language can produce it
"""

import base64
import hashlib
import os
import platform
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

import requests
import tomli, tomli_w
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DB_PATH = str(Path.home())+"/.menoa/attestation.db"
BIN_DIR = "/bin"

def create_table():
    """
    Creates the attestation database, one row per binary
    """
    conn = sqlite3.connect(DB_PATH)

    # The old table's validated flags came from inverted logic and can't be trusted, start over
    conn.execute("DROP TABLE IF EXISTS attestation")
    conn.execute('''
        CREATE TABLE IF NOT EXISTS binaries (
            path TEXT PRIMARY KEY,
            package TEXT,        -- NULL when no package owns the file, it can't be attested
            version TEXT,
            distro TEXT,
            arch TEXT,
            hash TEXT,           -- sha256 of the file at the last check, NULL if unreadable
            checked_at REAL,
            expected_hash TEXT,  -- from the server, NULL until attested
            signature TEXT
        )
    ''')

    conn.commit()
    conn.close()

def get_settings():
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["attestation"].get("server_url", ""), config["attestation"].get("public_key", "")

def system_identity():
    # The distro and CPU architecture, which together with the package version decide what a binary's hash should be
    os_release = platform.freedesktop_os_release()
    return f"{os_release.get('ID', 'unknown')} {os_release.get('VERSION_ID', '')}".strip(), platform.machine()

def signed_message(distro, arch, package, version, path, sha256):
    """
    The exact bytes the server signs for one binary. Every field is bound, so a record can't be moved to another path, package version, or system
    """
    return "\n".join(["menoa-attestation-v1", distro, arch, package, version, path, sha256]).encode()

def verify_record(public_key, distro, arch, package, version, path, sha256, signature):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key)).verify(
            base64.b64decode(signature), signed_message(distro, arch, package, version, path, sha256))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

def sha256_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()
    except OSError:
        return None

def list_binaries():
    # Symlinks are checked as the file they point to, which can be outside BIN_DIR (e.g. Ubuntu's coreutils live in /usr/lib)
    entries = (os.path.join(BIN_DIR, name) for name in os.listdir(BIN_DIR))
    return sorted({os.path.realpath(p) for p in entries if os.path.isfile(p)})

def get_package_owners(paths):
    """
    Returns {path: (package, version)} for every path a package owns, using one or two package manager calls in total
    """
    wanted = set(paths)
    owners = {}

    if shutil.which("dpkg-query"):
        result = subprocess.run(["dpkg-query", "-S", *paths], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            # "pkg: /path", "pkg1, pkg2: /path", or "pkg:arch: /path", diversion lines don't start with a package name
            package, _, path = line.partition(": ")
            if path in wanted and not line.startswith("diversion "):
                owners[path] = package.split(", ")[0].split(":")[0]

        versions = dict(line.split("\t", 1) for line in subprocess.run(
            ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"], capture_output=True, text=True).stdout.splitlines() if "\t" in line)
        return {path: (package, versions[package]) for path, package in owners.items() if package in versions}

    if shutil.which("rpm"):
        # %{=TAG} repeats a package's single value on each of its file lines
        result = subprocess.run(["rpm", "-qa", "--qf", "[%{FILENAMES}\t%{=NAME}\t%{=VERSION}-%{=RELEASE}\n]"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[0] in wanted:
                owners.setdefault(parts[0], (parts[1], parts[2]))
        return owners

    # /usr/games/pacman is a game on Debian, only trust pacman if its database exists
    if shutil.which("pacman") and os.path.isdir("/var/lib/pacman"):
        versions = dict(line.split(" ", 1) for line in subprocess.run(["pacman", "-Q"], capture_output=True, text=True).stdout.splitlines() if " " in line)
        for line in subprocess.run(["pacman", "-Ql"], capture_output=True, text=True).stdout.splitlines():
            package, _, path = line.partition(" ")
            if path in wanted and package in versions:
                owners.setdefault(path, (package, versions[package]))
        return owners

    return owners

def binary_status(row, public_key):
    """
    Works out a binary's status from its database row (path, package, version, distro, arch, hash, expected_hash, signature)
    """
    path, package, version, distro, arch, hash_value, expected_hash, signature = row

    if package is None:
        return "Not checkable"
    if hash_value is None:
        return "Unreadable"
    if signature is None:
        return "Pending"
    if not public_key or not verify_record(public_key, distro, arch, package, version, path, expected_hash, signature):
        return "Record tampered!"
    if hash_value != expected_hash:
        return "Tampered!"
    return "Validated"

STATUS_COLUMNS = "path, package, version, distro, arch, hash, expected_hash, signature"

def get_number_of_binaries():
    """
    Returns the total number of binaries in the database
    """
    create_table()
    conn = sqlite3.connect(DB_PATH)
    count = conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]
    conn.close()
    return count

def get_binary_data():
    """
    Returns (path, version, hash, status) for every binary in the database
    """
    create_table()
    _, public_key = get_settings()

    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(f"SELECT {STATUS_COLUMNS} FROM binaries ORDER BY path").fetchall()
    conn.close()

    return [(row[0], row[2], row[5], binary_status(row, public_key)) for row in rows]

def attest():
    """
    Hashes every binary in BIN_DIR, fetches signed expected hashes for new or upgraded ones, and alerts on tampering
    Returns {status: count}. Raises if the server couldn't be used, after the local check is done and saved
    """
    server_url, public_key = get_settings()
    if not server_url or not public_key:
        raise Exception("Set server_url and public_key under [attestation] in ~/.menoa/config.toml")

    create_table()
    distro, arch = system_identity()
    paths = list_binaries()
    owners = get_package_owners(paths)
    now = time.time()

    conn = sqlite3.connect(DB_PATH)
    known = {row[0]: row[1:] for row in conn.execute("SELECT path, package, version, distro, arch FROM binaries")}

    # Binaries that were removed from the system
    conn.executemany("DELETE FROM binaries WHERE path = ?", [(p,) for p in known.keys() - set(paths)])

    for path in paths:
        package, version = owners.get(path, (None, None))
        hash_value = sha256_file(path)

        if known.get(path) == (package, version, distro, arch):
            conn.execute("UPDATE binaries SET hash = ?, checked_at = ? WHERE path = ?", (hash_value, now, path))
        else:
            # New binary, or its package was upgraded: the old version's record no longer applies, replace it so the database keeps one row per binary
            conn.execute("INSERT OR REPLACE INTO binaries VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                         (path, package, version, distro, arch, hash_value, now))
    conn.commit()

    to_fetch = conn.execute("SELECT path, package, version FROM binaries WHERE package IS NOT NULL AND signature IS NULL").fetchall()
    server_error = None

    if to_fetch:
        try:
            response = requests.post(server_url.rstrip("/") + "/v1/attest", timeout=60, json={
                "distro": distro, "arch": arch,
                "binaries": [{"path": p, "package": pkg, "version": ver} for p, pkg, ver in to_fetch],
            })
            response.raise_for_status()
            records = response.json()["records"]

            rejected = 0
            for path, package, version in to_fetch:
                record = records.get(path)
                if not record:
                    continue
                # Only store records signed for exactly what we asked about
                if verify_record(public_key, distro, arch, package, version, path, record["sha256"], record["signature"]):
                    conn.execute("UPDATE binaries SET expected_hash = ?, signature = ? WHERE path = ?", (record["sha256"], record["signature"], path))
                else:
                    rejected += 1
            conn.commit()

            if rejected:
                server_error = f"{rejected} record(s) from the server had invalid signatures and were ignored"
        except Exception as e:
            server_error = f"Couldn't get records from the attestation server: {e}"

    rows = conn.execute(f"SELECT {STATUS_COLUMNS} FROM binaries").fetchall()
    conn.close()

    counts = {}
    flagged = []
    for row in rows:
        status = binary_status(row, public_key)
        counts[status] = counts.get(status, 0) + 1
        if status in ("Tampered!", "Record tampered!"):
            flagged.append(f"{row[0]}: {status}")

    if flagged:
        print("\n".join(flagged))
        try:
            from menoa.utils.utils import alert
            alert("Found tampered binaries", f"{len(flagged)} binaries failed attestation, e.g. {flagged[0]}")
        except Exception as e:
            print(f"Couldn't show desktop notification: {e}")

    if server_error:
        raise Exception(server_error)

    return counts

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
