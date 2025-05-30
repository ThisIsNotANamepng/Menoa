import shlex
import os

def load_script_template():
    """
    Returns a simple bash script template to get users started.
    """
    return ("#!/usr/bin/env bash\n"
            "# Sample script template\n"
            "# e.g.: update package list and install curl\n"
            "sudo apt-get update\n"
            "sudo apt-get install -y curl\n"
            "# Download a file\n"
            "# wget https://example.com/file.txt -O ./file.txt\n")

def parse_script(script_text):
    """
    Parse the bash script text into a list of command tokens.
    Skips blank lines and comments.
    """
    commands = []
    for raw_line in script_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        if tokens:
            commands.append(tokens)
    return commands

def predict_actions(parsed_commands):
    """
    Given a list of parsed command token lists, return a list of
    human-readable predictions of what each command will do.
    """
    predictions = []
    for tokens in parsed_commands:
        cmd = tokens[0]
        args = tokens[1:]
        desc = ''
        # File removal
        if cmd in ('rm', 'rm.exe'):
            desc = describe_rm(args)
        # Copy files
        elif cmd in ('cp', 'copy'):
            desc = describe_cp(args)
        # Move/rename
        elif cmd in ('mv', 'move'):
            desc = describe_mv(args)
        # Download
        elif cmd in ('wget', 'curl'):
            desc = describe_download(cmd, args)
        # Package managers
        elif cmd in ('apt-get', 'yum', 'dnf', 'brew', 'pacman'):
            desc = describe_package_manager(cmd, args)
        # Change permission/ownership
        elif cmd in ('chmod',):
            desc = describe_chmod(args)
        elif cmd in ('chown',):
            desc = describe_chown(args)
        else:
            desc = f"Would execute: {' '.join(tokens)}"
        predictions.append(desc)
    return predictions

# Helper describers

def describe_rm(args):
    if '-r' in args or '-rf' in args:
        paths = [a for a in args if not a.startswith('-')]
        target = paths or ['<paths>']
        return f"Recursively remove files/directories: {', '.join(target)}"
    else:
        return f"Remove files: {' '.join(args) if args else '<none specified>'}"


def describe_cp(args):
    if len(args) >= 2:
        src = args[-2]
        dst = args[-1]
        return f"Copy from {src} to {dst}"
    return "Copy command with insufficient arguments"


def describe_mv(args):
    if len(args) >= 2:
        src = args[-2]
        dst = args[-1]
        return f"Move/rename {src} to {dst}"
    return "Move command with insufficient arguments"


def describe_download(cmd, args):
    if cmd == 'wget':
        url = args[0] if args else '<url>'
        return f"Download file from {url} using wget"
    elif cmd == 'curl':
        return f"Transfer data with curl: {' '.join(args)}"
    return "Download command"


def describe_package_manager(cmd, args):
    action = ' '.join(args[:2]) if args else ''
    pkgs = args[2:] if len(args) > 2 else []
    return f"Run package manager {cmd}: {action} on packages {', '.join(pkgs) if pkgs else '<none>'}"


def describe_chmod(args):
    if len(args) >= 2:
        mode = args[0]
        target = args[1]
        return f"Change permissions of {target} to {mode}"
    return "chmod with insufficient arguments"


def describe_chown(args):
    if len(args) >= 2:
        owner = args[0]
        target = args[1]
        return f"Change owner of {target} to {owner}"
    return "chown with insufficient arguments"
