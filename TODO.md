# Bug fix TODO

Ordered by priority. Work top to bottom, one at a time.

## Critical

- [ ] **1. `menoa init` fails on a fresh machine**
  - [x] `os.fileexists` doesn't exist; desktop file also had indented keys, an unexpanded `~` icon path, and no applications dir
  - [x] Default network feed URL pointed at `127.0.0.1:5000`; now `plain` format at the Linode bucket, and one failing feed no longer stops `init`
  - [ ] Upload `network/main.txt` to the bucket, and make `process/process_analyses.pkl` public (both currently 403 AccessDenied); clam default URLs in config are unused placeholders
  - [x] `import utils.attestation_utils` breaks in the installed package
  - [x] GUI runs setup with a progress dialog on first launch; README install steps mention `menoa init`; cvdupdate now runs in-process (works for pipx/desktop launches) and once instead of three times
- [x] **2. Failed scan reports "No malware found!"**: scans with no signatures loaded, a crash, or a missing path now fail loudly (CLI exit 2, GUI "Scan failed"). Also fixed: symlinks, empty files and unreadable files were reported as malware; CLI exits 0/1/2 like clamscan
- [x] **3. Attestation logic is inverted**: rewritten around signed expected hashes (Ed25519). Local DB keeps one signed record per binary, rechecks are local, tampering with the DB shows "Record tampered!", tampered binaries raise a desktop alert
- [x] **4. Process scanner puts results on the wrong PID**: PIDs and results now line up; Menoa loads the `baseline_model.py` artifact (pipeline with its own encoders) instead of re-fitting `LabelEncoder`; live features match atop's vocabulary (POLI `norm`, Status `-`/`N`, State `I`→`S`, 15-char CMD); CPU is sampled over 1s. Same fixes in LinuxProcessesScanning's `testSystem.py`

## High

- [x] **5. GUI progress hits 100% at about 53%**: progress is now files done / total, held at 99.9% until clamscan finishes; `get_scan_total` counts exactly what clamscan prints (symlinks, unreadable dirs; verified 26,791/26,791 on /usr/share/doc)
- [x] **6. `delete_binary` binds `(path)`, not `(path,)`**: replaced by the rewrite
- [x] **7. `get_package_version` only supports pacman**: now dpkg, rpm and pacman, batched (tested on Ubuntu, Debian, Fedora, Arch)
- [x] **8. Custom clam feeds are never used in scans**: custom feeds from the config are passed to clamscan in every scan type (missing ones are skipped with a warning instead of breaking the scan); `utils` import restored so `clam reload <custom>` works; `--local-path` stored absolute. Verified real clamscan detects a file via a custom .hdb feed
- [x] **9. `menoa init` always overwrites `config.toml`**
- [x] **10. `cli.py` is a SyntaxError on Python 3.11**: nested same-quote f-strings in the `clam delay` / `network delay` commands. Fixed, every file in `menoa/`, `tests/` and `setup.py` parses on a real 3.11
- [x] **11. GUI won't open without clamscan or a system DB**; it also shows the system DB version, not Menoa's. Fixed, the version is read from Menoa's `daily.cvd` header. Found with it: scans only used Menoa's databases through symlinks in `quick/` `standard/` `deep/`, and where those were missing clamscan silently used the system database (or only custom feeds). Every scan now passes every configured database, and a missing default stops the scan
- [x] **12. Full scan of `/` walks `/proc`, `/sys`, `/dev`** (clamscan call and `get_scan_total`). Fixed, every scan skips mounts inside it by filesystem type (`SKIPPED_FILESYSTEMS`: kernel views, network shares, merged container/portal views); `/dev`, tmpfs, snaps and USB drives are still scanned

## Medium

- [x] **13. Dashboard**: cards don't navigate (`page_map` keys vs titles); Attestation card always shows Disabled. Fixed, cards carry their page index and config section; statuses and stats refresh whenever the dashboard is shown; placeholder stats replaced with signature age and last scan
- [ ] **14. `shell explain`**: crashes on a bare line ([cli.py:560-563](menoa/cli.py#L560-L563)); misses combined flags (`-rf`, `-xzf`), `sudo`, and pipes (`curl | bash`) ([script_utils.py](menoa/utils/script_utils.py))
- [x] **15. `predict` crashes**: model is loaded after download; exited/unreadable processes are skipped
- [ ] **16. Model download**: `joblib.load` of an unverified download (pin a sha256) ([process_utils.py](menoa/utils/process_utils.py)). Fixed: status check and atomic write. Your local `~/.menoa/process_scanner.pkl` is a saved 403 error page, delete it
- [x] **17. `menoa process scan` ignores the configured threshold**: defaults to the config value now
- [ ] **18. Hard-coded `/home/jack` icon paths**; `.desktop` uses unexpanded `~` ([utils.py:25](menoa/utils/utils.py#L25), [main.py:304](menoa/main.py#L304), [352](menoa/main.py#L352))
- [ ] **19. Versioned feeds**: network feeds fixed (versioning removed, pluggable formats). Clam still uses `progress_patch_download`: `current_version` never saved, patches re-append forever, `add_feed` omits `current_version` ([utils.py:75-107](menoa/utils/utils.py#L75-L107))
- [ ] **20. Network page**: fake interface summary ([network_utils.py](menoa/utils/network_utils.py)). Fixed: set lookup, normalized cache files, consistent threat counts
- [ ] **21. "Check System Binaries" blocks the GUI thread** for ~7-12s while hashing ~2.5k binaries ([attestation_page.py](menoa/pages/attestation_page.py)). Fixed: POST timeout, table refresh, result message

## Low

- [x] `clam_last_scanned/` check has a trailing slash, so the timestamp resets every init
- [ ] `clock.py` broken `utils.` import, runs at import time, bare `except` ([clock.py:3](menoa/clock.py#L3))
- [ ] `main.py` prints import timings on every launch
- [ ] `ClamPage._start_scan` connects lambdas to worker signals; Qt runs those on the worker thread, so they call `setText` off the GUI thread (connect bound widget methods instead)
- [ ] `clam_utils.scan_path` is dead code calling an undefined `parse_clamscan_output`
- [ ] `if not seconds`: a delay or threshold of 0 can't be set (CLI)
- [ ] Wrong CLI help text (process/attestation `toggle` say "network"; `attestation delay` says "Process")
- [ ] `combine_files` swallows errors; fixed `/tmp` download filename
- [x] Dead code: duplicate `toggle`, `attest_with_server` uses undefined `data`
- [ ] `build/lib/` is tracked in git despite `.gitignore`
- [ ] `setup.py`: `==` pins in `install_requires`; placeholder `author_email`/`url`

## To discuss

- [ ] **Deploying intel updates to clients.** Decide the default network feed source and how updates reach clients. Proposed: edit intel in a private MISP → VPS cron exports `restSearch` to a static `main.txt` → clients refresh on a schedule. Full-snapshot refresh already handles additions and deletions. Open pieces:
  - Where the default feed is hosted (Linode bucket, VPS nginx, GitHub), or use a public feed / no default
  - Clients never refresh on their own: `feed_update_delay` is unused, nothing runs `menoa network reload` on a schedule (systemd timer, or the roadmap's background clock)
  - VPS export script (cron: restSearch → upload)
  - Where the process model is hosted (`download_process_model` still uses the bucket)
- [ ] **Attestation server.** Client side is done ([attestation_utils.py](menoa/utils/attestation_utils.py) docstring has the API). Open pieces:
  - Build the server: look up the expected sha256 for (distro, arch, package, version, path) and sign `signed_message()` with the Menoa private key
  - Generate the Ed25519 key pair, keep the private key on the server only, put the public key and server URL in the default config
  - Limits: root malware can also edit Menoa's code or the configured public key; repointing a symlink in /bin to an unowned file shows as a new "Not checkable" binary, not an alert; package manager versions are trusted as reported
- [ ] **Process model training data.** CombinedSets.csv (TON_IoT) labels rows by *attack time window*, not by malicious process: `atop` itself is labelled malicious 20,862 times, and 189 of 328 process names appear under both labels. Status/POLI value `0` looks like a second export format and correlates with label 1. The model can't learn "this process is malware" from these labels; needs a dataset labelled per process (the readme's own-dataset idea). Also: random row split leaks the same processes/time windows into the test set, so reported metrics are optimistic; `algorithms/*.py` legacy scripts still use the old `LabelEncoder` approach and write `ProcessAnalyses.pkl` in the current directory
- [ ] **Keeping ClamAV signatures up to date.** Age warnings are done (ClamAV page, `menoa clam scan` warning with `--quiet`, `menoa clam status` exit codes), but nothing updates on its own, so they just tell the user. Open pieces:
  - Background updates without root: a user systemd timer (`systemctl --user`) running `menoa clam reload` a few times a day, same mechanism as the network feeds and the roadmap's background clock. ClamAV rate-limits mirrors (cvdupdate keeps its own cooldown), so not more often than every few hours
  - Desktop notification (`utils.alert`) at most once a day when signatures pass 7 days, or when updates keep failing (record the last successful update and last error so the two can be told apart)
  - `update_clamav_feed` always writes to `~/.menoa/feeds/clam`, ignoring the default feeds' `local_path` in the config
- [ ] **Full scans without root.** A non-root `menoa clam full` can't read much of `/`, so it reports thousands of "couldn't be scanned" items. Options: run as root (pkexec from the GUI, sudo from the CLI), or skip root-only system dirs quietly and say that system files need a root scan
