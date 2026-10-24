"""
Checks the CLI's delay and threshold settings, including 0. Run with `python tests/test_cli_settings.py` (or pytest)
"""

import os, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = tempfile.mkdtemp()
(Path.home() / ".menoa").mkdir()

import tomli
from click.testing import CliRunner
from menoa.cli import cli

CONFIG = Path.home() / ".menoa" / "config.toml"


def run(*args):
    return CliRunner().invoke(cli, list(args))


def test_zero_can_be_set():
    CONFIG.write_text("".join(f"[{tool}]\nscan_delay = 600\nfeed_update_delay = 600\nenabled = true\nthreshold = 0.7\n" for tool in ("clamav", "network", "process", "attestation")))

    for args, section, key in [
        (["clam", "delay", "0"], "clamav", "scan_delay"),
        (["clam", "delay", "--update", "0"], "clamav", "feed_update_delay"),
        (["network", "delay", "0"], "network", "scan_delay"),
        (["network", "delay", "--update", "0"], "network", "feed_update_delay"),
        (["process", "delay", "0"], "process", "scan_delay"),
        (["process", "threshold", "0"], "process", "threshold"),
        (["attestation", "delay", "0"], "attestation", "scan_delay"),
    ]:
        result = run(*args)
        assert result.exit_code == 0, (args, result.output)
        assert tomli.loads(CONFIG.read_text())[section][key] == 0, (args, CONFIG.read_text())

    # No value still shows the current one
    assert "Scan delay: 0" in run("clam", "delay").output
    assert "Threshold: 0" in run("process", "threshold").output


def test_out_of_range_values_are_rejected():
    # "--" so a negative number isn't read as an option (without it click rejects it as an unknown option)
    for args in (["process", "threshold", "1.5"], ["process", "threshold", "--", "-0.1"], ["clam", "delay", "--", "-5"], ["attestation", "delay", "--", "-1"]):
        result = run(*args)
        assert result.exit_code == 2 and "Invalid value" in result.output, (args, result.output)


def test_help_text_names_the_right_tool():
    for tool, word in (("process", "process"), ("attestation", "attestation"), ("network", "network")):
        assert f"Toggle {word} background" in run(tool, "toggle", "--help").output
    assert "attestation check delay" in run("attestation", "delay", "--help").output.lower()


if __name__ == "__main__":
    test_zero_can_be_set()
    test_out_of_range_values_are_rejected()
    test_help_text_names_the_right_tool()
    print("All CLI settings checks passed")
