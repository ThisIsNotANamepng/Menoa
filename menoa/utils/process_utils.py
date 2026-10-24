import pandas as pd
import joblib
import psutil
import os
import shutil
import time
import hashlib
import lzma
import json
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pathlib import Path
import tomli, tomli_w

MODEL_PATH = str(Path.home())+"/.menoa/process_scanner.pkl"
# Menoa's model ships inside the package, so it's never downloaded and new models come with Menoa releases
BUNDLED_MODEL = Path(__file__).resolve().parent.parent / "models" / "process_model.pkl.xz"
# Menoa's model, decompressed (LinuxProcessesScanning's ProcessAnalyses.pkl). It's extracted to MODEL_PATH, which is checked against
# this hash from the code on every load, so neither a planted file nor config.toml can change what Menoa's model is
BUILTIN_MODEL_SHA256 = "e57c03addc75284d914eceb3e9c057cfb2df315c4db6b8cefcff18fbdd8bda4b"
MAX_MODEL_BYTES = 1_000_000_000

def get_model_settings():
    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        process = tomli.load(f).get("process", {})

    # No model_url means Menoa's bundled model
    return {
        "model_url": process.get("model_url", ""),
        "model_public_key": process.get("model_public_key", ""),
    }

def is_official_model(settings):
    return not settings["model_url"]

def is_unsigned_model(settings):
    # A model the user added without a model_public_key, it's loaded without any check
    return not is_official_model(settings) and not settings["model_public_key"]

def model_public_key(settings):
    # The key the model must be signed with, None if it isn't signature checked
    if is_official_model(settings):
        return None  # Checked against BUILTIN_MODEL_SHA256 instead
    return settings["model_public_key"] or None

def model_message(version, sha256):
    # The exact bytes a model signature covers
    return f"menoa-model-v1\n{version}\n{sha256}".encode()

def verify_model(model_path, signature_path, settings):
    """
    Checks a model before it's loaded, loading a pickle runs code from it. Raises if it can't be trusted
    - Menoa's model (no model_url): it must be the bundled model, whatever config.toml says
    - A model_url with a model_public_key: signed with that key
    - A model_url without one: the user chose that model, it isn't checked
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

    try:
        with open(signature_path) as f:
            signed = json.load(f)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key)).verify(
            base64.b64decode(signed["signature"]), model_message(signed["version"], sha256))
    except FileNotFoundError:
        raise Exception(f"{model_path} has no signature file ({signature_path}), so it wasn't loaded")
    except (InvalidSignature, ValueError, TypeError, KeyError):
        raise Exception(f"{model_path} isn't signed by model_public_key in ~/.menoa/config.toml, so it wasn't loaded")

    return signed["version"]

def load_model():
    """
    Returns the model artifact made by LinuxProcessesScanning's baseline_model.py: {"model": sklearn Pipeline, "metadata": {...}}
    The pipeline holds its own encoders, so it takes the raw feature values. Installs the model if it's missing
    """
    settings = get_model_settings()
    if not os.path.exists(MODEL_PATH):
        install_process_model(settings=settings)

    # Checked on every load, not just on install, so a model replaced on disk isn't run either
    try:
        verify_model(MODEL_PATH, MODEL_PATH + ".sig", settings)
    except Exception:
        if not is_official_model(settings):
            raise
        # Left from an older Menoa release (or replaced on disk), extract this release's model again
        install_process_model(settings=settings)

    artifact = joblib.load(MODEL_PATH)

    if not isinstance(artifact, dict) or "model" not in artifact or "metadata" not in artifact:
        raise Exception(f"{MODEL_PATH} is an old model format, delete it so the current model is downloaded")

    return artifact

def get_model_version():
    # Loads the model and gets the embedded model version
    return load_model()["metadata"]["version"]

def install_process_model(progress=None, settings=None):
    """
    Installs the process model to MODEL_PATH: Menoa's bundled model, or the user's from model_url (a URL or a local path), with its
    signature from model_url + ".sig" if it's signature checked. A .xz is decompressed first, its signature is at the url without .xz
    + ".sig" and covers the decompressed model. Neither replaces the current model unless it passes verify_model()
    """
    from menoa.utils.utils import progress_download

    settings = settings or get_model_settings()
    signed = model_public_key(settings) is not None
    download, signature_download = MODEL_PATH + ".download", MODEL_PATH + ".sig.download"

    def fetch(source, destination, progress=None):
        if "://" in source:
            progress_download(source, destination, progress)
        else:
            shutil.copyfile(source, destination)

    url = settings["model_url"] or str(BUNDLED_MODEL)
    try:
        if url.endswith(".xz"):
            # Compressed to save bandwidth (and space in Menoa's package)
            fetch(url, download + ".xz", progress)
            decompress_model(download + ".xz", download)
        else:
            fetch(url, download, progress)
        if signed:
            fetch(url.removesuffix(".xz") + ".sig", signature_download)
        verify_model(download, signature_download, settings)

        os.replace(download, MODEL_PATH)
        if signed:
            os.replace(signature_download, MODEL_PATH + ".sig")
    finally:
        for leftover in (download, download + ".xz", signature_download):
            if os.path.exists(leftover):
                os.remove(leftover)

def decompress_model(source, destination):
    # Capped, so a hostile .xz can't fill the disk before the model is verified
    with lzma.open(source) as src, open(destination, "wb") as dst:
        while chunk := src.read(1 << 20):
            if dst.tell() + len(chunk) > MAX_MODEL_BYTES:
                raise Exception(f"Decompressed process model is over {MAX_MODEL_BYTES // 1_000_000} MB, it wasn't used")
            dst.write(chunk)

def set_model(source=None, public_key=""):
    """
    Switches to the model at `source` (a URL or a local path), or back to Menoa's model with no source. With a public_key it must be
    signed with that key, without one a model other than Menoa's isn't checked. The config only changes once the new model is installed
    and passes verify_model()
    """
    if source and "://" not in source:
        source = os.path.abspath(os.path.expanduser(source))
    settings = {"model_url": source or "", "model_public_key": public_key if source else ""}
    install_process_model(settings=settings)

    with open(str(Path.home())+"/.menoa/config.toml", "rb") as f:
        config = tomli.load(f)
    process = config.setdefault("process", {})
    if source:
        process.update(settings)
    else:
        process.pop("model_url", None)
        process.pop("model_public_key", None)
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
