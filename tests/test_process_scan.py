"""
Checks that process scan results land on the right PIDs and that live features match the training data's vocabulary
Run with `python tests/test_process_scan.py` (or pytest). Uses a stub model, so no real model is needed
"""

import os, subprocess, sys, time
from pathlib import Path

import numpy as np
import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from menoa.utils import process_utils

FEATURES = ['TRUN', 'TSLPI', 'TSLPU', 'POLI', 'NICE', 'PRI', 'RTPR', 'Status', 'State', 'CPU', 'CMD']


class FlagsNiceProcesses:
    # Stub model: "malicious" exactly when NICE is 19, so a shifted PID would flag the wrong process
    def predict_proba(self, features):
        assert list(features.columns) == FEATURES
        p = (features["NICE"] == 19).astype(float).to_numpy()
        return np.column_stack([1 - p, p])


def test_results_line_up_with_pids():
    process_utils.load_model = lambda: {"model": FlagsNiceProcesses(), "metadata": {"feature_columns": FEATURES, "version": "test"}}
    niced = subprocess.Popen(["nice", "-n", "19", "sleep", "30"])
    normal = subprocess.Popen(["sleep", "30"])
    try:
        pids, predictions, confidences = process_utils.predict(0.5)
        assert len(pids) == len(predictions) == len(confidences) > 10
        assert all(isinstance(p, int) for p in pids)

        flagged = {pid for pid, pred in zip(pids, predictions) if pred == "Malicious"}
        assert niced.pid in flagged and normal.pid not in flagged
        for pid in flagged:
            assert psutil.Process(pid).nice() == 19, pid
    finally:
        niced.kill()
        normal.kill()


def test_features_use_training_vocabulary():
    child = subprocess.Popen(["sleep", "30"])
    try:
        time.sleep(0.2)
        features = process_utils.process_features(psutil.Process(child.pid), time.time())
        assert features["POLI"] == "norm"
        assert features["Status"] == "N"          # started within atop's interval
        assert features["State"] in "DERSTZ"      # States seen in training
        assert features["PRI"] == 120 and features["NICE"] == 0
        assert features["CMD"] == "sleep"
        assert features["TSLPI"] == 1 and features["TRUN"] == 0

        old = process_utils.process_features(psutil.Process(1), time.time() + process_utils.ATOP_INTERVAL)
        assert old["Status"] == "-"
    finally:
        child.kill()


if __name__ == "__main__":
    test_results_line_up_with_pids()
    test_features_use_training_vocabulary()
    print("All process scan checks passed")
