import pandas as pd
import joblib
import psutil
import os
import shutil
import time
import hashlib
import json
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pathlib import Path
import tomli, tomli_w

MODEL_PATH = str(Path.home())+"/.menoa/process_scanner.pkl"
DEFAULT_MODEL_URL = "https://menoa-feeds.us-ord-1.linodeobjects.com/process%2Fprocess_analyses.pkl"
# Menoa's own model is checked against this key from the code, never the one in config.toml, so editing the config can't make
# Menoa's model_url accept another model. Base64 Ed25519 public key from `menoa process keygen`
MENOA_MODEL_PUBLIC_KEY = ""
# Until MENOA_MODEL_PUBLIC_KEY is set, Menoa's model_url only accepts this model (LinuxProcessesScanning's ProcessAnalyses.pkl)
# shortcut: only until Menoa's model signing key exists, then set MENOA_MODEL_PUBLIC_KEY and delete this
BUILTIN_MODEL_SHA256 = "e57c03addc75284d914eceb3e9c057cfb2df315c4db6b8cefcff18fbdd8bda4b"

def get_model_settings():
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        process = tomli.load(f).get("process", {})

    # Configs made before these settings existed get the defaults
    return {
        "model_url": process.get("model_url", DEFAULT_MODEL_URL),
        "model_public_key": process.get("model_public_key", ""),
    }

def is_official_model(settings):
    return settings["model_url"] == DEFAULT_MODEL_URL

def is_unsigned_model(settings):
    # A model the user added without a model_public_key, it's loaded without any check
    return not is_official_model(settings) and not settings["model_public_key"]

def model_public_key(settings):
    # The key the model must be signed with, None if it isn't signature checked
    if is_official_model(settings):
        return MENOA_MODEL_PUBLIC_KEY or None
    return settings["model_public_key"] or None

def model_message(version, sha256):
    # The exact bytes a model signature covers
    return f"menoa-model-v1\n{version}\n{sha256}".encode()

def verify_model(model_path, signature_path, settings):
    """
    Checks a model before it's loaded, loading a pickle runs code from it. Raises if it can't be trusted
    - Menoa's model_url: signed with MENOA_MODEL_PUBLIC_KEY (or the built-in model until that's set), whatever config.toml says
    - Another model_url with a model_public_key: signed with that key
    - Another model_url without one: the user chose that model, it isn't checked
    Returns the signed version, "built-in", or None if it isn't checked
    The signature file is JSON: {"version": "<model version>", "signature": "<base64 Ed25519 signature of model_message()>"}
    """
    if is_unsigned_model(settings):
        return None

    with open(model_path, "rb") as f:
        sha256 = hashlib.file_digest(f, "sha256").hexdigest()

    public_key = model_public_key(settings)
    if public_key is None:
        if sha256 == BUILTIN_MODEL_SHA256:
            return "built-in"
        raise Exception(f"{model_path} isn't Menoa's built-in model, so it wasn't loaded. To use your own model run `menoa process model <path or url>`")

    signer = "Menoa" if is_official_model(settings) else "model_public_key in ~/.menoa/config.toml"
    try:
        with open(signature_path) as f:
            signed = json.load(f)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key)).verify(
            base64.b64decode(signed["signature"]), model_message(signed["version"], sha256))
    except FileNotFoundError:
        raise Exception(f"{model_path} has no signature file ({signature_path}), so it wasn't loaded")
    except (InvalidSignature, ValueError, TypeError, KeyError):
        raise Exception(f"{model_path} isn't signed by {signer}, so it wasn't loaded")

    return signed["version"]

def load_model():
    """
    Returns the model artifact made by LinuxProcessesScanning's baseline_model.py: {"model": sklearn Pipeline, "metadata": {...}}
    The pipeline holds its own encoders, so it takes the raw feature values. Downloads the model if it's missing
    """
    if not os.path.exists(MODEL_PATH):
        download_process_model()

    # Checked on every load, not just on download, so a model replaced on disk isn't run either
    verify_model(MODEL_PATH, MODEL_PATH + ".sig", get_model_settings())

    artifact = joblib.load(MODEL_PATH)

    if not isinstance(artifact, dict) or "model" not in artifact or "metadata" not in artifact:
        raise Exception(f"{MODEL_PATH} is an old model format, delete it so the current model is downloaded")

    return artifact

def get_model_version():
    # Loads the model and gets the embedded model version
    return load_model()["metadata"]["version"]

def download_process_model(progress=None, settings=None):
    """
    Gets the process model from model_url (a URL or a local path), and its signature from model_url + ".sig" if a model_public_key is set.
    Neither replaces the current model unless the download passes verify_model()
    """
    print("Process model not found, downloading...")

    from menoa.utils.utils import progress_download

    settings = settings or get_model_settings()
    signed = model_public_key(settings) is not None
    download, signature_download = MODEL_PATH + ".download", MODEL_PATH + ".sig.download"

    def fetch(source, destination, progress=None):
        if "://" in source:
            progress_download(source, destination, progress)
        else:
            shutil.copyfile(source, destination)

    try:
        fetch(settings["model_url"], download, progress)
        if signed:
            fetch(settings["model_url"] + ".sig", signature_download)
        verify_model(download, signature_download, settings)

        os.replace(download, MODEL_PATH)
        if signed:
            os.replace(signature_download, MODEL_PATH + ".sig")
    finally:
        for leftover in (download, signature_download):
            if os.path.exists(leftover):
                os.remove(leftover)

def set_model(source=None, public_key=""):
    """
    Switches to the model at `source` (a URL or a local path). With a public_key it must be signed with that key, without one
    a model other than Menoa's isn't checked. The config only changes once the new model is installed and passes verify_model()
    """
    source = source or DEFAULT_MODEL_URL
    if "://" not in source:
        source = os.path.abspath(os.path.expanduser(source))
    settings = {"model_url": source, "model_public_key": public_key}
    download_process_model(settings=settings)

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)
    config.setdefault("process", {}).update(settings)
    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

def generate_signing_key(private_key_path):
    """
    Writes a new Ed25519 private key for signing models, readable only by you, and returns its base64 public key for model_public_key
    """
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

    # O_EXCL: never overwrite an existing key, models signed with it would stop loading
    with os.fdopen(os.open(private_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        f.write(base64.b64encode(raw).decode() + "\n")

    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

def sign_model(model_path, private_key_path, version=None):
    """
    Signs a model with a key from generate_signing_key(), writing model_path + ".sig" to publish next to it
    The version defaults to the one inside the model (metadata.version), returns the version signed
    """
    if version is None:
        version = str(joblib.load(model_path)["metadata"]["version"])

    with open(private_key_path) as f:
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(f.read().strip()))
    with open(model_path, "rb") as f:
        sha256 = hashlib.file_digest(f, "sha256").hexdigest()

    with open(model_path + ".sig", "w") as f:
        json.dump({"version": version, "signature": base64.b64encode(key.sign(model_message(version, sha256))).decode()}, f)
    return version

def get_process_threshold():
    """
    Gets the threshold for process scanning
    """
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)
    
    return config["process"]["threshold"]

def set_process_threshold(threshold):
    """
    Sets the threshold for process scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["process"]["threshold"] = threshold

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

ATOP_INTERVAL = 10  # The training data is atop output, whose Status "N" means the process started during its 10s default interval

# Scheduling policy names as atop prints them
POLICY_NAMES = {os.SCHED_OTHER: "norm", os.SCHED_BATCH: "btch", os.SCHED_IDLE: "idle", os.SCHED_FIFO: "fifo", os.SCHED_RR: "rr"}

def read_stat(path):
    # Fields of a /proc/.../stat file after the command name, which can contain spaces: [state, ppid, ..., priority (15), nice (16), ...]
    with open(path, "r") as f:
        return f.read().rsplit(")", 1)[1].split()

def atop_state(state):
    # Kernels since 4.14 report idle kernel threads as "I", atop (and the training data) counted them as sleeping
    return "S" if state == "I" else state

def process_features(proc, now):
    """
    Reads one process's features the way atop recorded them in the training data
    """
    pid = proc.pid
    stat = read_stat(f"/proc/{pid}/stat")

    threads = {"R": 0, "S": 0, "D": 0}
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            state = atop_state(read_stat(f"/proc/{pid}/task/{tid}/stat")[0])
        except FileNotFoundError:
            continue  # Thread exited while being read
        if state in threads:
            threads[state] += 1

    with open(f"/proc/{pid}/comm", "r") as f:
        cmd = f.read().strip()  # atop shows the kernel's 15 character command name

    return {
        'TRUN': threads["R"],
        'TSLPI': threads["S"],
        'TSLPU': threads["D"],
        'POLI': POLICY_NAMES.get(os.sched_getscheduler(pid) & ~os.SCHED_RESET_ON_FORK, "unknown"),
        'NICE': int(stat[16]),
        'PRI': int(stat[15]) + 100,
        'RTPR': os.sched_getparam(pid).sched_priority,
        'Status': "N" if now - proc.create_time() < ATOP_INTERVAL else "-",
        'State': atop_state(stat[0]),
        'CPU': proc.cpu_percent(None),
        'CMD': cmd,
    }

def predict(threshold: float=0.75):
    """
    Scans running processes, returns (pids, predictions, confidences) where the three lists line up index by index
    """
    artifact = load_model()
    model = artifact["model"]

    processes = list(psutil.process_iter())

    # cpu_percent() compares against the previous call, so the first reading is always 0
    for proc in processes:
        try:
            proc.cpu_percent(None)
        except psutil.Error:
            pass
    time.sleep(1)

    now = time.time()
    pids = []
    rows = []
    for proc in processes:
        try:
            row = process_features(proc, now)
        except (psutil.Error, OSError):
            continue  # Exited or unreadable, skip it so pids and rows stay aligned
        pids.append(proc.pid)
        rows.append(row)

    if not rows:
        return ([], [], [])

    features = pd.DataFrame(rows).reindex(columns=artifact["metadata"]["feature_columns"])
    malicious_probabilities = model.predict_proba(features)[:, 1]

    predictions = []
    confidences = []
    for prob_malicious in malicious_probabilities:
        if prob_malicious >= threshold:
            predictions.append("Malicious")
            confidences.append(float(prob_malicious))
        else:
            predictions.append("benign")
            confidences.append(float(1 - prob_malicious))

    return (pids, predictions, confidences)


def set_scanning_delay(seconds):
    """
    Sets the delay for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["process"]["scan_delay"] = seconds

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

def set_scanning_threshold(threshold):
    """
    Sets the threshold for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    config["process"]["threshold"] = threshold

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

def get_scanning_delay():
    """
    Returns the delay for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["process"]["scan_delay"]

def get_scanning_threshold():
    """
    Returns the threshold for scanning
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    return config["process"]["threshold"]

def toggle(status=None):
    """
    Toggles scanning, reverses current status if nothing is passed
    """

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)

    current = config["process"]["enabled"]

    if status is None:
        config["process"]["enabled"] = not current
    else:
        config["process"]["enabled"] = status

    with open(str(Path.home())+"/.menoa/config.toml", "wb") as f:
        tomli_w.dump(config, f)

    if status is None: return not current
    else: return status
