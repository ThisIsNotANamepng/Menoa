# Linux Security Center

I want to build a good AV for Linux, but it needs to follow some good design goals which follow Linux principles

- Needs to get out of the way
- Focus on intelligent, important features and minimal bloat
- Scriptable

To that end, I think it should have the following tools

- ClamAV powered antivirus
- Process scanning (ML with those datasets)
    - Could learn based on the user’s behavior, alert when unusual behavior happens
    - Could make our own damn dataset, UNSW-NB15 has ~920000 benign and ~110000 malicious traces
        - We could have the cyber club attack a box
            - Maybe even for malware night
- Take a command and try to predict what will happen to the system
    - Should do de-obsfucation
    - Could take a bash script
        - For example, when a software needs to be installed with a bash script the tool could scan it to find anything malicious
- System Attestation, check binary file hashes against an api with known good hashes
- Basic network analysis, search every foreign address the system connects to against a threat feed of bad ips/domains

And also

- Should also be options to turn any of the above tools on/off
- Should be able to run and be useful without root

Note: This is not a security scanner, it is not for finding all security flaws within a system. There are tools such as Lynis for that. This tool is only meant to include some features which detect continuous threats to a typical desktop system

## ClamAV Frontend

### Updating signatures

`freshclam` needs root to run, so unless we can get a window to open just to get root for that (which I can't figure out) I think the best option is to maintain our own feed which is downloaded and used instead of the clamav feed. I don't like it, but I think it's the only way. It can be stored on the central server, and be base don the actual clamav feed + yarify from abuse.ch

Note: With `clamscan --version` you get smething like: ClamAV 1.4.2/27649/Mon May 26 03:31:06 2025, this is ClamAV Version/threat feed database version (increments by 1 every update)/Last time the database was updated on their end. If we could find where they say the current database version, we could check for out of date local version

## Network Monitoring

## Process Classification

## Binary Attestation

### Local database

When you redraw the gui you don't want to re-check every binary against the api because the binaries are unlikely to have changed. It would be more efficient to cache a local database with all of the binaries that have been checked and the result of the check

## Command Parsing

## To Install

### Linux

1. Make a new Python virtual environment (optional but highly encouraged): `python3 -m venv env` and activate `source env/bin/activate`

2. Install Python requirments: `pip install -r requirements.txt`

3. Install ClamAV: `sudo <package-manager> install clamav`

4. Run `cd gui`, `python3 main.py`

### Windows

1. Switch to Linux

2. See the steps for Linux installation

## Technical Details

### Config and Internal Files

The datasets and configs will be kept in `~/.menoa`

#### Custom feeds

Menoa allows you to add your own custom feeds for malware scanning signatures and ip address endpoints

This is an example feed (a default one packaged with Menoa)

    [clam_feeds.default_daily]
    url = "menoa.org/feed.default"              # Upstream url to re-download from. If the feed is a one-time, non-updating dataset just set this to the same as `local_path`
    name = "Default daily.cvd ClamAV feed"      # Name of the feed
    description = "Daily bundled with ClamAV"   # One line description of the feed
    local_path = ~/.menoa/feeds/daily.cvd       # The local path to the current feed dataset on the system (must be read available to the user running Menoa)
    last_refreshed = 1970-01-01T00:00:00        # The last time the dataset was re-downloaded from `url`
    upstream_supports_versioning = True         # Whether or not the upstream download `url` supports versioning, allowing to download the changes to a feed dataset instead of redownloadig the entire dataset every time it's redownloaded. See 'Upstream Versioning' for more information

### Upstream Versioning

Feeds may have upstream_supports_versioning set to True which means that the server or location which hosts the upstream feed dataset can take the version that the local dataset is at, allowing it to just reply with the changes made since the given version, saving network costs

#TODO Add technical details here

## TODO:

- [ ] Find a better threat feed for urls, I think they can be smaller and more specific to these needs, also I think this feeds might only be for malware distribution and not contain things like c&c servers (https://urlhaus.abuse.ch/api/#csv)
- [ ] You can only get the ip addresses of foreign connections, not domains. Some (I'm assuming) urls are on the threat feed but not the ip addresses of those domains, so they aren't detected. We need to resolve the domains on the list to ips or the ips on the system to domains. It would probably be easiest to do this on the download server for the threat feeds (I'm assuming there will be a server controlled by me for this)
- [ ] Should network monitoring include ipv6? Right now it doesn't
- [ ] I want the ClamAV scanning to run a different color circle as it loads the signatures
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

#### Progress:

- [x] ClamAV functions
- [ ] Process scanning model
- [x] Process continuous scanning
- [x] System command testing
- [ ] Make a good de-obsfucator
- [x] Binary attestation client
- [ ] Binary attestation server
- [x] Network monitoring
- [ ] Good background scanning

- [x] Process scanning GUI
- [x] ClamAV GUI
- [x] Command testing GUI
- [ ] Binary attestation GUI
- [x] Network monitoring GUI
