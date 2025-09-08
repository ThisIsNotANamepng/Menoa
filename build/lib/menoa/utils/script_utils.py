import shlex
from typing import List, Dict, Any
import requests

def load_remote_script(url) -> str:
    """
    Returns the text from a remote url
    """

    if url[0:4] != "http":
        url = "https://" + url

    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.text

def load_local_script(path: str) -> str:
    """
    Returns the text from a local file path
    """
    
    with open(path, "r") as f:
        return f.read()

def parse_script(script_text: str) -> List[Dict[str, Any]]:
    """
    Parses bash script text into structured command objects
    Returns list of command dictionaries with line number, command, and arguments
    """
    commands = []
    lines = script_text.splitlines()

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comments and empty lines
        if not stripped or stripped.startswith('#'):
            continue

        try:
            # Handle basic command splitting (ignores complex shell features)
            tokens = shlex.split(stripped)
            if tokens:
                commands.append({
                    "line": line_num,
                    "command": tokens[0],
                    "args": tokens[1:]
                })
        except ValueError:
            # Skip malformed lines (unclosed quotes, etc.)
            continue

    return commands

def predict_actions(parsed_commands: List[Dict[str, Any]]) -> List[str]:
    """
    Predicts system actions from parsed command structures
    Returns human-readable action descriptions
    """
    predictions = []

    for cmd in parsed_commands:
        line = cmd.get("line", "?")
        command = cmd.get("command", "")
        args = cmd.get("args", [])

        # Utilities for flags and targets
        flags = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        flags_str = " ".join(flags)
        tgt_str = ", ".join(targets) or "[items]"

        # Command-specific predictions
        if command in ["rm"]:
            action = "Recursively deletes" if "-r" in flags else "Deletes"
            predictions.append(f"Line {line}: {action} {tgt_str} {flags_str}".strip())

        elif command == "mkdir":
            action = "Creates directory path (with parents)" if "-p" in flags else "Creates directory"
            for d in targets:
                predictions.append(f"Line {line}: {action} {d} {flags_str}".strip())

        elif command in ["cp", "mv"]:
            if len(targets) >= 2:
                src = ", ".join(targets[:-1])
                dest = targets[-1]
                action = "Copies" if command == "cp" else "Moves"
                predictions.append(f"Line {line}: {action} {src} → {dest} {flags_str}".strip())

        elif command == "ln":
            if "-s" in flags:
                pred = f"Line {line}: Creates symbolic link {tgt_str} {flags_str}"
            else:
                pred = f"Line {line}: Creates hard link {tgt_str} {flags_str}"
            predictions.append(pred)

        elif command in ["echo"]:
            if any(op in args for op in [">", ">>"]):
                for op in [">>", ">"]:
                    if op in args:
                        idx = args.index(op)
                        fname = args[idx+1] if idx+1 < len(args) else "[file]"
                        verb = "Appends to" if op == ">>" else "Overwrites"
                        predictions.append(f"Line {line}: {verb} {fname} with output")
                        break
            else:
                predictions.append(f"Line {line}: Outputs text to console")

        elif command in ["cat"]:
            predictions.append(f"Line {line}: Reads/concatenates file(s) {tgt_str}")

        elif command in ["grep", "egrep", "fgrep"]:
            pattern = targets[0] if targets else "[pattern]"
            path = targets[1] if len(targets) > 1 else "."
            predictions.append(f"Line {line}: Searches for pattern '{pattern}' in {path} {flags_str}")

        elif command == "find":
            path = targets[0] if targets else "."
            if "-delete" in flags:
                predictions.append(f"Line {line}: Finds and deletes matching files in {path} {flags_str}")
            else:
                predictions.append(f"Line {line}: Finds files in {path} matching {flags_str}")

        elif command in ["awk"]:
            predictions.append(f"Line {line}: Processes text with awk script {tgt_str}")

        elif command in ["sed"]:
            predictions.append(f"Line {line}: Edits streams/text with sed script {tgt_str}")

        elif command == "tar":
            if "-x" in flags:
                predictions.append(f"Line {line}: Extracts archive {tgt_str} {flags_str}")
            elif "-c" in flags:
                predictions.append(f"Line {line}: Creates archive {tgt_str} {flags_str}")
            else:
                predictions.append(f"Line {line}: Manages tar archive {tgt_str} {flags_str}")

        elif command in ["zip", "unzip"]:
            act = "Creates zip archive" if command == "zip" else "Extracts zip archive"
            predictions.append(f"Line {line}: {act} {tgt_str} {flags_str}")

        elif command in ["wget", "curl"]:
            url = targets[-1] if targets else "[URL]"
            verb = "Downloads" if command == "wget" else "Transfers data from"
            predictions.append(f"Line {line}: {verb} {url} {flags_str}")

        elif command in ["scp", "rsync"]:
            src = targets[0] if targets else "[src]"
            dest = targets[1] if len(targets) > 1 else "[dest]"
            verb = "Copies files over SSH" if command == "scp" else "Synchronizes files"
            predictions.append(f"Line {line}: {verb} {src} → {dest} {flags_str}")

        elif command == "ssh":
            host = targets[-1] if targets else "[host]"
            predictions.append(f"Line {line}: Connects to remote host {host} via SSH {flags_str}")

        elif command in ["ps"]:
            predictions.append(f"Line {line}: Lists processes {flags_str}")

        elif command in ["kill", "killall"]:
            preds = "Terminates processes" if command == "killall" else "Sends signal to process"
            predictions.append(f"Line {line}: {preds} {tgt_str} {flags_str}")

        elif command == "systemctl":
            sub = targets[0] if targets else "[action]"
            svc = targets[1] if len(targets) > 1 else "[service]"
            predictions.append(f"Line {line}: {sub.capitalize()} service {svc} {flags_str}")

        elif command == "service":
            act = targets[0] if targets else "[action]"
            svc = targets[1] if len(targets) > 1 else "[service]"
            predictions.append(f"Line {line}: {act.capitalize()} service {svc}")

        elif command == "journalctl":
            predictions.append(f"Line {line}: Views system logs {flags_str}")

        elif command in ["df", "du"]:
            predictions.append(f"Line {line}: Reports filesystem usage {flags_str} {tgt_str}")

        elif command == "mount":
            predictions.append(f"Line {line}: Mounts {tgt_str} {flags_str}")

        elif command == "umount":
            predictions.append(f"Line {line}: Unmounts {tgt_str}")

        elif command == "dd":
            predictions.append(f"Line {line}: Copies and converts data {flags_str}")

        elif command in ["useradd", "userdel", "groupadd", "groupdel"]:
            preds = {
                "useradd": "Adds user",
                "userdel": "Deletes user",
                "groupadd": "Adds group",
                "groupdel": "Deletes group",
            }[command]
            predictions.append(f"Line {line}: {preds} {tgt_str} {flags_str}")

        elif command == "passwd":
            predictions.append(f"Line {line}: Changes password for {tgt_str}")

        elif command == "chroot":
            predictions.append(f"Line {line}: Changes root directory to {tgt_str}")

        elif command == "su":
            user = targets[0] if targets else "root"
            predictions.append(f"Line {line}: Switches user to {user} {flags_str}")

        elif command == "cron" or command == "crontab":
            predictions.append(f"Line {line}: Schedules tasks in cron {flags_str} {tgt_str}")

        elif command in ["alias", "export"]:
            predictions.append(f"Line {line}: Sets shell alias/variable {tgt_str}")

        elif command in ["uname", "hostname", "whoami", "id"]:
            predictions.append(f"Line {line}: Queries system/user info {command}")

        elif command in ["uptime", "top", "htop"]:
            predictions.append(f"Line {line}: Shows system resource usage {command}")

        elif command in ["apt", "apt-get", "yum", "pacman", "brew", "dnf"]:
            action = "Manages packages"
            predictions.append(f"Line {line}: {action} {flags_str} {tgt_str}")

        elif command in ["git"]:
            sub = targets[0] if targets else "[subcommand]"
            predictions.append(f"Line {line}: Executes git {sub} {flags_str}")

        else:
            # Generic fallback
            predictions.append(f"Line {line}: Executes command {command} {flags_str} {tgt_str}".strip())

    return predictions if predictions else ["No actionable commands detected"]
