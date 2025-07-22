import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import joblib
import psutil
import os
import time

def get_tslpi(pid):
    tslpi = 0
    task_dir = f'/proc/{pid}/task'

    try:
        for tid in os.listdir(task_dir):
            status_file = os.path.join(task_dir, tid, 'status')
            with open(status_file, 'r') as f:
                for line in f:
                    if line.startswith('State:'):
                        state = line.split()[1]  # e.g., 'S' for interruptible sleep
                        if state == 'S':
                            tslpi += 1
                        break
    except Exception as e:
        print(f"Error accessing task info: {e}")
        return None

    return tslpi

def get_tslpu(pid):
    tslpu = 0
    task_dir = f'/proc/{pid}/task'

    try:
        for tid in os.listdir(task_dir):
            status_file = os.path.join(task_dir, tid, 'status')
            with open(status_file, 'r') as f:
                for line in f:
                    if line.startswith('State:'):
                        state = line.split()[1]  # e.g., 'D' for uninterruptible sleep
                        if state == 'D':
                            tslpu += 1
                        break
    except Exception as e:
        print(f"Error accessing task info: {e}")
        return None

    return tslpu

def get_process_state(pid):
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('State:'):
                    state_code = line.split()[1]  # e.g., 'S', 'R', 'D', etc.
                    return state_code.lower()  # return as 's', 'r', etc. to match your dataset
    except FileNotFoundError:
        return 'e'  # Process exited
    except Exception as e:
        print(f"Error reading status for PID {pid}: {e}")
        return '?'

def get_trun(pid):
    trun = 0
    task_dir = f'/proc/{pid}/task'

    try:
        for tid in os.listdir(task_dir):
            status_file = os.path.join(task_dir, tid, 'status')
            with open(status_file, 'r') as f:
                for line in f:
                    if line.startswith('State:'):
                        state = line.split()[1]  # 'R', 'S', etc.
                        if state == 'R':
                            trun += 1
                        break
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

    return trun

def predict(threshold: float):

    # Load the trained model
    rf_classifier = joblib.load('ProcessAnalyses.pkl')

    # Columns: ['TRUN', 'TSLPI', 'TSLPU', 'POLI', 'NICE', 'PRI', 'RTPR', 'CPUNR', 'Status', 'State', 'CPU', 'CMD', 'label']

    # Get the current processes
    pids = ["padding"]

    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'status', 'create_time', 'memory_percent', 'cpu_percent']):
        try:
            # Get process details as a dictionary
            info = proc.info

            pid = info['pid']
            pids.append(pid)

            # RTPR and POLI
            poli = os.sched_getscheduler(pid)
            ## In the dataset this is either 'norm' or 0, in practice its always 0
            param  = os.sched_getparam(pid)
            rtpr = param.sched_priority

            # TSLPI and TSLPU

            tslpi = get_tslpi(pid)
            tslpu = get_tslpu(pid)

            # State

            ## State of E is not a standard state, read paper to see what it is, right now it's mapped to dead (X)
            state = get_process_state(pid).upper()

            # TRUN
            trun = get_trun(pid)

            processes.append({
                'TRUN': trun,
                'TSLPI': tslpi,
                'TSLPU': tslpu,
                'POLI': poli,
                'NICE': proc.nice(),
                'PRI': 20 + proc.nice() + 100,
                'RTPR': rtpr,
                'Status': info['status'],
                'State': state,
                'CPU': info['cpu_percent'],
                'CMD': info['name']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Create a DataFrame from the processes
    test_data = pd.DataFrame(processes)

    # Preprocess the test data (same preprocessing steps as in training)
    le = LabelEncoder()
    for col in test_data.columns:
        if test_data[col].dtype == 'object':
            test_data[col] = le.fit_transform(test_data[col])

    X_test = test_data
    y_test = [0] * len(X_test)  # Target variable (all benign)

    # Make predictions on the test data
    y_pred = rf_classifier.predict(X_test)

    y_proba = rf_classifier.predict_proba(X_test)

    malicious_count = 0
    benign_count = 0
    total = 0

    predictions = []
    confidences = []


    for i, probs in enumerate(y_proba):
        total +=1

        prob_malicious = probs[1]  # Probability of class 1
        prob_benign = probs[0]
        pred_class = 1 if prob_malicious >= threshold else 0

        if pred_class == 1:
            predictions.append("Malicious")
            confidences.append(prob_malicious)

            malicious_count += 1
        else:
            predictions.append("benign")
            confidences.append(prob_benign)

            benign_count += 1
        
    return (pids, predictions, confidences)