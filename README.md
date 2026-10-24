# Menoa

Menoa is a modern, scriptable security tool designed solely for Linux. Its goal is to provide robust malware detection and system monitoring, following Linux principles.. Menoa is not a vulnerability scanner, but a focused security companion for everyday system safety. It's the Linux version of Microsoft Defender, not Lynis

## CURRENTLY UNDER DEVELOPMENT. NOT IN A USABLE STATE YET

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

## Network Threat Feeds

Menoa's default feed is just one source, you can add or replace feeds with anything that serves IP addresses. Each feed in `~/.menoa/config.toml` has a `format`:

| Format | Needs | Source |
|---|---|---|
| `plain` | `url` | One IP (or URL with an IP host) per line, `#` starts a comment. Any static file host works |
| `csv` | `url`, `column` | A CSV, `column` is a header name or a 0-based column number |
| `misp` | `url`, `api_key_env` | A [MISP](https://www.misp-project.org/) server, Menoa pulls `ip-src`/`ip-dst` attributes marked for IDS from published events, minus anything on enabled warninglists |
| `command` | `command` | Any command that prints one indicator per line, for TAXII, vendor APIs, or your own scripts |

`url` can also be a local path. Values that aren't valid IPs are dropped.

```
menoa network add --index mine --name "My feed" --description "Internal blocklist" --format plain --url https://example.org/ips.txt
menoa network add --index corp --name "Corp MISP" --description "Our MISP" --format misp --url https://misp.corp.example --api-key-env MENOA_MISP_KEY
menoa network add --index feodo --name "Feodo Tracker" --description "abuse.ch botnet C2 IPs" --format csv --url https://feodotracker.abuse.ch/downloads/ipblocklist.csv --column dst_ip
menoa network reload
```

To write your own server, serve a `plain` file.

### Hosting feeds with less bandwidth

- Menoa sends the `ETag`/`Last-Modified` it got last time, so an unchanged file costs a tiny `304 Not Modified`. nginx and S3-style object storage do this on their own
- Files served with `Content-Encoding: gzip` are decompressed by Menoa. For object storage, upload the gzipped file with that header, e.g. `gzip -9k main.txt && s3cmd put --add-header="Content-Encoding: gzip" --mime-type=text/plain main.txt.gz s3://<bucket>/network/main.txt`
- Your own process model's `model_url` can end in `.xz`, it's decompressed (`xz -9k model.pkl`, about 6x smaller). Its signature stays at `model.pkl.sig`

## Process Models

Menoa's own model ships inside Menoa (new models come with Menoa updates), and it's checked against a hash in Menoa's code before it's loaded, since loading a model runs code from it. To use your own model:

```
menoa process model ./my_model.pkl     # A local path or a URL, loaded unsigned since you chose it (scans point this out, -q hides it)
menoa process model --default          # Back to Menoa's model
```

To publish a model for other people, sign it so they only load your exact file:

```
menoa process keygen ~/menoa-model.key        # Prints your public key, keep the private key offline
menoa process sign model.pkl --key ~/menoa-model.key
```

Serve `model.pkl` and `model.pkl.sig` side by side. Users run `menoa process model https://example.org/model.pkl --public-key <key>`, or set `model_url` and `model_public_key` in the `[process]` section of `~/.menoa/config.toml`.

## Software Principles

Menoa is made specifically for Linux, and it follows the very important principles of the OS that users demand

- Needs to get out of the way
- Focus on intelligent, important features and minimal bloat
- Scriptable

## To Install

### Linux

1. Install with pip: `pip install menoa`

2. Install ClamAV with your package manager: `sudo apt install clamav`, `sudo dnf install clamav`, `sudo pacman -S clamav`

3. Run `menoa init`, or just open `menoa-gui`, which sets itself up on first launch. This creates `~/.menoa` and downloads the ClamAV signature databases (a few hundred MB), so the first run takes a few minutes

### Windows

1. Switch to Linux

2. See the steps for Linux installation

## Roadmap:

### Big changes:

- [ ] Add a clock to have Menoa run in the background (probably with systemd)
- [ ] Add feed management to the GUI

### Small changes:

- [ ] Resolve local ip addresses connected to by processes and compare to urls distrubuted in threat feeds
- [ ] Find a better threat feed for urls, I think they can be smaller and more specific to these needs, also I think this feeds might only be for malware distribution and not contain things like c&c servers (https://urlhaus.abuse.ch/api/#csv)
- [ ] Should network monitoring include ipv6? Right now it doesn't
- [ ] When clamav scanning is running, the progress % text line should be in the middle of the circle
- [ ] Right now ClamAV just uses the official source but you can load your own yara rules, we could make our own threat feed for yara rules combining other sources
- [ ] Add ability to run attestation after /bin and associated dirs are changed (after a package update)
- [ ] Add ability to scan with clam using a specified feed (cli and gui)
- [ ] Should you be able to determine how often a feed should update in the config?
- [ ] In GUI be able to stop a scan mid scan without having to close the window
- [ ] Any malware that tampers with a binary could also change its hash value in the database (the local database that marks a binary as attested), add a method of signing the hashes received from the api with a key from Menoa
- [ ] Change the load template button on the command page be a button that pops up an input box for you to put a link to a bash file, it downloads and analyzes (meant for install.sh files)
- [ ] Make the dashboard, left column, and overall qss (including unified colors and icon) better
- [ ] Add comments, clean up code
- [ ] Right now the attestation get package version function only uses pacman, add more package managers
- [ ] Update the last_checked column in the attestation database
- [ ] Pip doesn't automatically update, add an opt-in setting to have Menoa update itself automatically in the background
- [x] Get rid of quick/, standard/, and deep/ directories in favor of using the config to determine which feeds to use for each scan
- [ ] Add option to do different types of scans in the GUI
- [ ] Add util to completely redownload feeds, getting rid of past feed signatures
- [ ] Process scanning returns processes above the threshold as beningn, but only some
- [ ] Add a status option for cli tools to see whether background work is on or off
- [ ] Right now when the process scanning model or the attestation table isn't found it is automatically downloaded without user interact, should this stay like this?
- [x] Running a clam scan, the progress circle fills up and progresss says 100% before scanning is complete (files: 153, nested files: 10027), could be an error in the counting of nested files for total files to scan for progress bar
- [ ] Make opening the gui faster
- [ ] Across all tools, make all options available with the cli also available in the gui
- [ ] Attestation versioning isn't working
- [ ] Set up attestation api
- [ ] Write more info for learn more buttons on the dashboard
- [ ] Have instructions to install clamav when not detected, fail gracefully when its not installed

Written by [Jack Hagen](https://hagen.rip)
