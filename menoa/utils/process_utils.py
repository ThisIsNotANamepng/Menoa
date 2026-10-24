import pandas as pd
import joblib
import psutil
import os
import time
from pathlib import Path
import tomli, tomli_w

MODEL_PATH = str(Path.home())+"/.menoa/process_scanner.pkl"

def load_model():
    """
    Returns the model artifact made by LinuxProcessesScanning's baseline_model.py: {"model": sklearn Pipeline, "metadata": {...}}
    The pipeline holds its own encoders, so it takes the raw feature values. Downloads the model if it's missing or unreadable
    """
    try:
        artifact = joblib.load(MODEL_PATH)
    except Exception:
        download_process_model()
        artifact = joblib.load(MODEL_PATH)

    if not isinstance(artifact, dict) or "model" not in artifact or "metadata" not in artifact:
        raise Exception(f"{MODEL_PATH} is an old model format, delete it so the current model is downloaded")

    return artifact

def get_model_version():
    # Loads the model and gets the embedded model version
    return load_model()["metadata"]["version"]

def download_process_model(progress=None):
    # Downloads the latest process model from the menoa servers
    print("Process model not found, downloading...")

    from menoa.utils.utils import progress_download

    url = "https://menoa-feeds.us-ord-1.linodeobjects.com/process%2Fprocess_analyses.pkl"
    progress_download(url, MODEL_PATH, progress)

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
