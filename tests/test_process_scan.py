"""
Checks that process scan results land on the right PIDs and that live features match the training data's vocabulary
Run with `python tests/test_process_scan.py` (or pytest). Uses a stub model, so no real model is needed
"""

import contextlib, hashlib, json, os, subprocess, sys, tempfile, threading, time
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from unittest import mock
from pathlib import Path

import joblib
import tomli
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
    stub = {"model": FlagsNiceProcesses(), "metadata": {"feature_columns": FEATURES, "version": "test"}}
    niced = subprocess.Popen(["nice", "-n", "19", "sleep", "30"])
    normal = subprocess.Popen(["sleep", "30"])
    try:
        with mock.patch.object(process_utils, "load_model", lambda: stub):
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


class Planted:
    # Loading this pickle creates `marker`, the way a malicious model would run its code
    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return (open, (self.marker, "w"))


@contextlib.contextmanager
def model_home(**process_settings):
    """A temporary HOME with these [process] settings and MODEL_PATH inside it, never the real ~/.menoa"""
    home = Path(tempfile.mkdtemp())
    (home / ".menoa").mkdir()
    # JSON strings and booleans are valid TOML
    (home / ".menoa" / "config.toml").write_text("[process]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in process_settings.items()))
    model = home / ".menoa" / "process_scanner.pkl"
    with mock.patch.dict(os.environ, {"HOME": str(home)}), mock.patch.object(process_utils, "MODEL_PATH", str(model)):
        yield model


OWN_URL = "https://example.org/model.pkl"  # Any model_url but Menoa's


def new_key():
    path = Path(tempfile.mkdtemp()) / "model.key"
    return path, process_utils.generate_signing_key(str(path))


def assert_refused(expected, marker):
    try:
        process_utils.load_model()
        assert False, f"should have refused: {expected}"
    except Exception as e:
        assert expected in str(e), e
    assert not marker.exists(), "the untrusted model was run"


def test_signed_models_load():
    key, public = new_key()
    assert key.stat().st_mode & 0o777 == 0o600
    with model_home(model_public_key=public, model_url=OWN_URL) as model:
        joblib.dump({"model": "stub", "metadata": {"version": "1.2.0"}}, model)
        assert process_utils.sign_model(str(model), str(key)) == "1.2.0"  # Version read from the model
        assert process_utils.load_model()["model"] == "stub"


def test_untrusted_models_never_run():
    key, public = new_key()
    other_key, _ = new_key()
    marker = Path(tempfile.mkdtemp()) / "ran"

    with model_home(model_public_key=public, model_url=OWN_URL) as model:
        signature = Path(str(model) + ".sig")
        joblib.dump(Planted(str(marker)), model)
        assert_refused("has no signature file", marker)

        process_utils.sign_model(str(model), str(other_key), "1.0")
        assert_refused("isn't signed by model_public_key", marker)

        # A trusted model replaced on disk after it was signed
        joblib.dump({"model": "stub", "metadata": {"version": "1.0"}}, model)
        process_utils.sign_model(str(model), str(key))
        joblib.dump(Planted(str(marker)), model)
        assert_refused("isn't signed by model_public_key", marker)

        signature.write_text("not json")
        assert_refused("isn't signed by model_public_key", marker)

    with model_home() as model:  # Menoa's model: a replaced file is swapped back for the bundled model, not run
        joblib.dump(Planted(str(marker)), model)
        assert process_utils.load_model()["metadata"]["version"] == "0.2.0" and not marker.exists()


def test_own_models_load_unsigned():
    # A model_url the user chose, without a model_public_key, isn't checked
    own = Path(tempfile.mkdtemp()) / "own.pkl"
    joblib.dump({"model": "own", "metadata": {"version": "dev"}}, own)
    with model_home(model_url=str(own)) as model:
        assert process_utils.load_model()["model"] == "own"  # Copied from the local path
        assert model.exists()


def test_model_download():
    key, public = new_key()
    marker = Path(tempfile.mkdtemp()) / "ran"
    served = Path(tempfile.mkdtemp())
    joblib.dump({"model": "stub", "metadata": {"version": "2.0"}}, served / "model.pkl")
    process_utils.sign_model(str(served / "model.pkl"), str(key))
    server = HTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(served)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    settings = {"model_public_key": public, "model_url": f"http://127.0.0.1:{server.server_port}/model.pkl"}

    try:
        with model_home(**settings) as model:
            assert process_utils.load_model()["model"] == "stub"  # Downloaded with its signature
            assert sorted(os.listdir(model.parent)) == ["config.toml", "process_scanner.pkl", "process_scanner.pkl.sig"]

        # A compromised server swaps the model, the download is deleted without being loaded
        joblib.dump(Planted(str(marker)), served / "model.pkl")
        with model_home(**settings) as model:
            assert_refused("isn't signed by model_public_key", marker)
            assert os.listdir(model.parent) == ["config.toml"]

        (served / "model.pkl.sig").unlink()
        with model_home(**settings) as model:
            assert_refused("404", marker)
            assert os.listdir(model.parent) == ["config.toml"]
    finally:
        server.shutdown()


def test_cli_keygen_and_sign():
    from click.testing import CliRunner
    from menoa.cli import cli

    folder = Path(tempfile.mkdtemp())
    key = folder / "menoa-model.key"
    result = CliRunner().invoke(cli, ["process", "keygen", str(key)])
    assert result.exit_code == 0, result.output
    public = result.output.split('model_public_key = "')[1].split('"')[0]

    original = key.read_text()
    result = CliRunner().invoke(cli, ["process", "keygen", str(key)])
    assert result.exit_code == 1 and key.read_text() == original, result.output  # Never overwritten

    joblib.dump({"model": "stub", "metadata": {"version": "3.1"}}, folder / "model.pkl")
    result = CliRunner().invoke(cli, ["process", "sign", str(folder / "model.pkl"), "--key", str(key)])
    assert result.exit_code == 0 and "version 3.1" in result.output, result.output
    settings = {"model_public_key": public, "model_url": "https://example.org/model.pkl"}
    assert process_utils.verify_model(str(folder / "model.pkl"), str(folder / "model.pkl.sig"), settings) == "3.1"


def test_cli_model():
    from click.testing import CliRunner
    from menoa.cli import cli

    folder = Path(tempfile.mkdtemp())
    joblib.dump({"model": "own", "metadata": {"version": "dev"}}, folder / "own.pkl")
    joblib.dump({"model": "unsigned", "metadata": {"version": "dev"}}, folder / "unsigned.pkl")
    joblib.dump({"model": "menoa", "metadata": {"version": "0.2.0"}}, folder / "menoa.pkl")
    _, public = new_key()
    config = lambda: tomli.loads((Path(os.environ["HOME"]) / ".menoa" / "config.toml").read_text())["process"]

    with model_home(threshold=0.7) as model:
        cwd = os.getcwd()
        os.chdir(folder)
        try:
            result = CliRunner().invoke(cli, ["process", "model", "own.pkl"])  # Relative paths are stored absolute
        finally:
            os.chdir(cwd)
        assert result.exit_code == 0, result.output
        assert config()["model_url"] == str(folder / "own.pkl") and config()["threshold"] == 0.7
        assert process_utils.load_model()["model"] == "own"
        assert "not signature checked" in CliRunner().invoke(cli, ["process", "model"]).output

        # A key that the model isn't signed with: nothing changes
        result = CliRunner().invoke(cli, ["process", "model", str(folder / "unsigned.pkl"), "--public-key", public])
        assert result.exit_code == 1 and "Model not changed" in result.output, result.output
        assert config()["model_url"] == str(folder / "own.pkl") and process_utils.load_model()["model"] == "own"

        # Back to Menoa's model, which has to be the built-in one again
        menoa_sha256 = hashlib.sha256((folder / "menoa.pkl").read_bytes()).hexdigest()
        with mock.patch.multiple(process_utils, BUNDLED_MODEL=folder / "menoa.pkl", BUILTIN_MODEL_SHA256=menoa_sha256):
            result = CliRunner().invoke(cli, ["process", "model", "--default"])
            assert result.exit_code == 0, result.output
            assert process_utils.load_model()["model"] == "menoa"
            assert "built-in" in CliRunner().invoke(cli, ["process", "model"]).output


def test_menoa_model_is_always_the_bundled_one():
    # Someone who can edit files as the user plants a model, signs it, and sets their key in config.toml:
    # Menoa's model is still only ever the one bundled with Menoa (pinned by hash in the code), the planted one never runs
    attacker_key, attacker_public = new_key()
    marker = Path(tempfile.mkdtemp()) / "ran"

    with model_home(model_public_key=attacker_public) as model:
        joblib.dump(Planted(str(marker)), model)
        process_utils.sign_model(str(model), str(attacker_key), "9.9")
        assert process_utils.load_model()["metadata"]["version"] == "0.2.0"
        assert not marker.exists(), "the planted model was run"
        assert hashlib.sha256(model.read_bytes()).hexdigest() == process_utils.BUILTIN_MODEL_SHA256  # Extracted again


def test_unsigned_model_warning():
    from click.testing import CliRunner
    from menoa.cli import cli

    _, public = new_key()
    warning = "your own unsigned process model (/models/own.pkl)"
    with mock.patch.object(process_utils, "predict", lambda threshold: ([], [], [])):
        with model_home(model_url="/models/own.pkl"):
            result = CliRunner().invoke(cli, ["process", "scan", "--threshold", "0.5"])
            assert result.exit_code == 0 and warning in result.stderr and warning not in result.stdout, result.output
            for quiet in ("--quiet", "-q"):
                result = CliRunner().invoke(cli, ["process", "scan", "--threshold", "0.5", quiet])
                assert result.exit_code == 0 and "unsigned" not in result.output, result.output

        # Checked models aren't pointed out
        for settings in ({"model_url": "/models/own.pkl", "model_public_key": public}, {}):
            with model_home(**settings):
                assert "unsigned" not in CliRunner().invoke(cli, ["process", "scan", "--threshold", "0.5"]).output

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from menoa.pages import process_page
    app = QApplication.instance() or QApplication([])
    with mock.patch.object(process_page, "get_model_version", lambda: "test"):
        with model_home(model_url="/models/own.pkl", threshold=0.5):
            page = process_page.ProcessPage(process_page.PredictionEngine())
            assert page.model_warning.text() == "Using your own unsigned model: /models/own.pkl" and not page.model_warning.isHidden()
            wait_for_model(app, page)  # Its background load finishes while the patch is still on
        with model_home(threshold=0.5):
            page = process_page.ProcessPage(process_page.PredictionEngine())
            assert page.model_warning.text() == "" and page.model_warning.isHidden()
            wait_for_model(app, page)


def wait_for_model(app, page):
    end = time.time() + 10
    while time.time() < end and page.version_label.text().endswith("loading..."):
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()


def test_gui_opens_without_waiting_for_the_model():
    # Loading the real model takes over a second, the Process page loads it in the background instead of holding up the window
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from menoa.pages import process_page
    app = QApplication.instance() or QApplication([])

    def slow_version():
        time.sleep(1)
        return "slow"

    with mock.patch.object(process_page, "get_model_version", slow_version), model_home(threshold=0.5):
        start = time.time()
        page = process_page.ProcessPage(process_page.PredictionEngine())
        assert time.time() - start < 0.8, time.time() - start
        assert page.version_label.text() == "Model version: loading..." and not page.scan_button.isEnabled()
        wait_for_model(app, page)
        assert page.version_label.text() == "Model version: slow" and page.scan_button.isEnabled()

    def broken_version():
        raise Exception("no model")

    with mock.patch.object(process_page, "get_model_version", broken_version), model_home(threshold=0.5):
        page = process_page.ProcessPage(process_page.PredictionEngine())
        wait_for_model(app, page)
        assert page.version_label.text() == "Model version: unavailable"


def test_bundled_model_is_the_trained_model():
    import lzma
    assert hashlib.sha256(lzma.decompress(process_utils.BUNDLED_MODEL.read_bytes())).hexdigest() == process_utils.BUILTIN_MODEL_SHA256

    # The model LinuxProcessesScanning produces, when it's checked out next to Menoa
    trained = Path(__file__).resolve().parent.parent.parent / "LinuxProcessesScanning" / "ProcessAnalyses.pkl"
    if trained.exists():
        assert hashlib.sha256(trained.read_bytes()).hexdigest() == process_utils.BUILTIN_MODEL_SHA256, "retrained: update the bundled model and its hash"


def test_upgrade_replaces_the_old_model():
    # A model extracted by an older Menoa release fails the new hash, it's replaced by this release's model
    with model_home() as model:
        joblib.dump({"model": "old release", "metadata": {"version": "0.1.0"}}, model)
        assert process_utils.load_model()["metadata"]["version"] == "0.2.0"


if __name__ == "__main__":
    test_results_line_up_with_pids()
    test_features_use_training_vocabulary()
    test_signed_models_load()
    test_untrusted_models_never_run()
    test_own_models_load_unsigned()
    test_model_download()
    test_cli_keygen_and_sign()
    test_cli_model()
    test_menoa_model_is_always_the_bundled_one()
    test_unsigned_model_warning()
    test_gui_opens_without_waiting_for_the_model()
    test_bundled_model_is_the_trained_model()
    test_upgrade_replaces_the_old_model()
    print("All process scan checks passed")
