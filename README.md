# Menoa

Menoa is a modern, scriptable security tool designed solely for Linux. Its goal is to provide robust malware detection and system monitoring, following Linux principles.. Menoa is not a vulnerability scanner, but a focused security companion for everyday system safety. It's the Linux version of Microsoft Defender, not Lynis

## Utilities

It is made up of five main tools,

- ClamAV-powered Antivirus
    - Provides a CLI and GUI frontend for ClamAV, the most popular open source antivirus*
- Network Connection Endpoint scanning
    - Compares outgoing IP address connections against lists of known malicious endpoints*
- Machine Learning Driven Process Classification (beta)
    - Not AI bloat, but an intelligent, lightweight way to detect running malware. Work is ongoing and is currently unusable
- Bash Parser (beta)
    - Takes an input bash script and explains what the script does in English. Allows the input of remote scripts (aimed as install.sh scripts)
- Binary Attestation
    - Verifies the hashes of local system binaries with an api providing known good hashes

\* The threat intelligence are driven by feeds provided by open source feeds collated by Menoa

## Software Principles

Menoa is made specifically for Linux, and it follows the very important principles of the OS that users demand

- Needs to get out of the way
- Focus on intelligent, important features and minimal bloat
- Scriptable

And also

- Should also be options to turn any of the above tools on/off
- Should be able to run and be useful without root


## To Install

### Linux

1. Install with pip: `pip install menoa`

2. Install ClamAV with your package manager: `sudo apt install clamav`, `sudo dnf install clamav`, `sudo pacman -S clamav`

### Windows

1. Switch to Linux

2. See the steps for Linux installation

## Roadmap:

### Big changes:

- [ ] Add a clock to have Menoa run in the background

### Other features:

- [ ] Find a better threat feed for urls, I think they can be smaller and more specific to these needs, also I think this feeds might only be for malware distribution and not contain things like c&c servers (https://urlhaus.abuse.ch/api/#csv)
- [ ] Should network monitoring include ipv6? Right now it doesn't
- [ ] When clamav scanning is running, the progress % text line should be in the middle of the circle
- [ ] Right now ClamAV just uses the official source but you can load your own yara rules, we could make our own threat feed for yara rules combining other sources
- [ ] Add ability to run attestation after /bin and associated dirs are changed (after a package update)
- [ ] Add ability to scan with clam using a specified feed (cli and gui)
- [ ] Should you be able to determine how often a feed should update in the config?
- [ ] In GUI be able to stop a scan mid scan without having to close the window
- [ ] Any malware that tampers with a binary could also change its hash value in the database, add a method of signing the hashes received from the api with a key from Menoa
- [ ] Change the load template button on the command page be a button that pops up an input box for you to put a link to a bash file, it downloads and analyzes (meant for install.sh files)
- [ ] Make the dashboard, left column, and overall qss (including unified colors and icon) better
- [ ] Add comments, clean up code
- [ ] Right now the attestation get package version function only uses pacman, add more package managers
- [ ] Right now downloading versioned feeds combines the temp downloaded file and main file, it put all info on one line, so the feed file is one long line, fix it with newlines
- [ ] Right now when downloading a versioned feed it doesn't mark the new patch version anywhere, add a place for the current patch version in the config and make it overwrite it when updated 
- [ ] Update the last_checked column in the attestation database

Written by [Jack Hagen](https://hagen.rip)