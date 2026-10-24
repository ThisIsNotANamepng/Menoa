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
- [ ] **3. Attestation logic is inverted**
  - [ ] Server statuses are discarded for sent binaries, and unmentioned ones are marked Validated ([attestation_utils.py:254-274](menoa/utils/attestation_utils.py#L254-L274))
  - [ ] Validated rows are never rechecked (`WHERE validated != 1`, [line 238](menoa/utils/attestation_utils.py#L238))
  - [ ] Local tamper detection only prints ([line 173](menoa/utils/attestation_utils.py#L173))
- [ ] **4. Process scanner puts results on the wrong PID**
  - [ ] `pids = ["padding"]` off-by-one, plus processes skipped after `pids.append` ([process_utils.py:142-151](menoa/utils/process_utils.py#L142-L151))
  - [ ] `LabelEncoder` re-fit on live data each scan ([line 195](menoa/utils/process_utils.py#L195))
  - [ ] First `cpu_percent` reading is always 0.0

## High

- [ ] **5. GUI progress hits 100% at about 53%**: `else` branch double-counts ([clam_page.py](menoa/pages/clam_page.py), `Scanner.scan`). Fixed: summary lines no longer counted as files
- [ ] **6. `delete_binary` binds `(path)`, not `(path,)`**: error is swallowed and `update_database` aborts ([attestation_utils.py:337](menoa/utils/attestation_utils.py#L337))
- [ ] **7. `get_package_version` only supports pacman**: returns `None` on apt/dnf, a dict when no manager is found ([attestation_utils.py:113-150](menoa/utils/attestation_utils.py#L113-L150))
- [ ] **8. Custom clam feeds are never used in scans**; `utils` import is commented out ([clam_utils.py:10](menoa/utils/clam_utils.py#L10), [174](menoa/utils/clam_utils.py#L174), [228](menoa/utils/clam_utils.py#L228))
- [x] **9. `menoa init` always overwrites `config.toml`**
- [ ] **10. `cli.py` is a SyntaxError on Python 3.11**: nested same-quote f-strings ([cli.py:229](menoa/cli.py#L229), 231, 360, 362)
- [ ] **11. GUI won't open without clamscan or a system DB**; it also shows the system DB version, not Menoa's ([clam_utils.py:96](menoa/utils/clam_utils.py#L96), [109](menoa/utils/clam_utils.py#L109))
- [ ] **12. Full scan of `/` walks `/proc`, `/sys`, `/dev`** (clamscan call and `get_scan_total`)

## Medium

- [ ] **13. Dashboard**: cards don't navigate (`page_map` keys vs titles); Attestation card always shows Disabled ([main.py:106](menoa/main.py#L106), [238-292](menoa/main.py#L238-L292))
- [ ] **14. `shell explain`**: crashes on a bare line ([cli.py:560-563](menoa/cli.py#L560-L563)); misses combined flags (`-rf`, `-xzf`), `sudo`, and pipes (`curl | bash`) ([script_utils.py](menoa/utils/script_utils.py))
- [ ] **15. `predict` crashes**: model downloaded but never loaded; `ProcessLookupError` not caught ([process_utils.py:133-154](menoa/utils/process_utils.py#L133-L154))
- [ ] **16. Model download**: `joblib.load` of an unverified download (pin a sha256) ([process_utils.py](menoa/utils/process_utils.py)). Fixed: status check and atomic write. Your local `~/.menoa/process_scanner.pkl` is a saved 403 error page, delete it
- [ ] **17. `menoa process scan` ignores the configured threshold** (0.75 vs config 0.7 vs GUI 0.6) ([cli.py:405](menoa/cli.py#L405))
- [ ] **18. Hard-coded `/home/jack` icon paths**; `.desktop` uses unexpanded `~` ([utils.py:25](menoa/utils/utils.py#L25), [main.py:304](menoa/main.py#L304), [352](menoa/main.py#L352))
- [ ] **19. Versioned feeds**: network feeds fixed (versioning removed, pluggable formats). Clam still uses `progress_patch_download`: `current_version` never saved, patches re-append forever, `add_feed` omits `current_version` ([utils.py:75-107](menoa/utils/utils.py#L75-L107))
- [ ] **20. Network page**: fake interface summary ([network_utils.py](menoa/utils/network_utils.py)). Fixed: set lookup, normalized cache files, consistent threat counts
- [ ] **21. "Check System Binaries" blocks the GUI thread**; POST has no timeout; table not refreshed ([attestation_page.py:20](menoa/pages/attestation_page.py#L20))

## Low

- [x] `clam_last_scanned/` check has a trailing slash, so the timestamp resets every init
- [ ] `clock.py` broken `utils.` import, runs at import time, bare `except` ([clock.py:3](menoa/clock.py#L3))
- [ ] `main.py` prints import timings on every launch
- [ ] `ClamPage._start_scan` connects lambdas to worker signals; Qt runs those on the worker thread, so they call `setText` off the GUI thread (connect bound widget methods instead)
- [ ] `clam_utils.scan_path` is dead code calling an undefined `parse_clamscan_output`
- [ ] `if not seconds`: a delay or threshold of 0 can't be set (CLI)
- [ ] Wrong CLI help text (process/attestation `toggle` say "network"; `attestation delay` says "Process")
- [ ] `combine_files` swallows errors; fixed `/tmp` download filename
- [ ] Dead code: duplicate `toggle`, `attest_with_server` uses undefined `data`
- [ ] `build/lib/` is tracked in git despite `.gitignore`
- [ ] `setup.py`: `==` pins in `install_requires`; placeholder `author_email`/`url`

## To discuss

- [ ] **Deploying intel updates to clients.** Decide the default network feed source and how updates reach clients. Proposed: edit intel in a private MISP → VPS cron exports `restSearch` to a static `main.txt` → clients refresh on a schedule. Full-snapshot refresh already handles additions and deletions. Open pieces:
  - Where the default feed is hosted (Linode bucket, VPS nginx, GitHub), or use a public feed / no default
  - Clients never refresh on their own: `feed_update_delay` is unused, nothing runs `menoa network reload` on a schedule (systemd timer, or the roadmap's background clock)
  - VPS export script (cron: restSearch → upload)
  - Where the process model is hosted (`download_process_model` still uses the bucket)
