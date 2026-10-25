# Building and publishing Menoa's feeds

Notes for whoever builds the server side: what clients expect, what was decided, and which sources to use.

## What the server publishes

| Feed | Built by the server? | Where clients get it |
|---|---|---|
| Network (`main.txt`) | Yes | `https://menoa-feeds.us-ord-1.linodeobjects.com/network/main.txt` (`[network_feeds.main]` in the default config) |
| YARA rules (`menoa.yar`) | Yes, planned | Not in the default config yet (`[yara_feeds]`), see [YARA rules](#yara-rules) |
| ClamAV signatures | No | Straight from `database.clamav.net` through cvdupdate on the client |
| Process model | No | Ships inside the Menoa package, pinned by `BUILTIN_MODEL_SHA256` in [process_utils.py](../menoa/utils/process_utils.py). A new model means a new Menoa release |

So the server's jobs are `main.txt` and, once it's added to the default config, `menoa.yar`.

## What clients expect from `main.txt`

- **Format:** `plain`, one IP per line. Text after `#` or the first space is ignored, so you can write `203.0.113.5 # ThreatFox Cobalt Strike`. IPv4 and IPv6 both work.
- **Exact IPs only.** CIDR ranges (`192.0.2.0/24`) are dropped, so expand them or leave them out. Supporting ranges is a small client change if you want Spamhaus DROP.
- **Every download is the whole list.** Clients replace their copy each time, with no change files and no versioning. To remove an IP, leave it out of the next file.
- **A file with no valid IPs is rejected.** The client keeps its previous data, so an HTML error page or a truncated upload can't wipe it.
- **Bandwidth:** clients send `If-None-Match`/`If-Modified-Since`, so an unchanged file costs a 304. Upload it gzipped with `Content-Encoding: gzip`:

  ```
  gzip -9k main.txt
  s3cmd put --acl-public --add-header="Content-Encoding: gzip" --mime-type=text/plain main.txt.gz s3://<bucket>/network/main.txt
  ```

  Keep `--acl-public`. Without it the bucket returns 403 and every client's `menoa network reload` fails.

## Decisions

- **No DNS on the client, forward or reverse.** Looking up every connection or every feed domain costs the client too much, and shared hosting causes too many false positives (one malware URL on `github.com` would flag all of GitHub). Domain-only entries are dropped.
- **IP-hosted URLs are reduced to the IP.** `http://100.100.100.100:8080/evil` becomes `100.100.100.100`. The client already does this, but do it on the server so the file stays small. Nobody legitimate serves files from a raw IP, so the false-positive risk is low.
- **The port is lost.** After reducing, a connection to that IP on any port matches. That's acceptable only if entries are fresh (next point).
- **Age entries out.** Cloud and VPS IPs get reassigned to harmless customers after the attacker leaves. Only include entries seen in the last 30 days, or marked online, and let older ones drop off. This matters more for false positives than anything else here.
- **Prefer C2 lists over attacker lists.** Menoa checks the remote address of every connection, incoming ones included. Lists of scanners and brute-forcers would flag every SSH attempt on a public server, so they don't belong in `main`.

## Sources

Checked on 2026-10-24.

| Source | What it is | Use? | Notes |
|---|---|---|---|
| [ThreatFox](https://threatfox.abuse.ch/export/) (abuse.ch) | C2 `ip:port`, domains and URLs, tagged with the malware family and a confidence score | **Yes, main source** | Needs a free abuse.ch Auth-Key, since the public exports return 410 Gone: `https://threatfox-api.abuse.ch/v2/files/exports/<KEY>/full.csv.zip`. Keep `ioc_type` = `ip:port`, take the part before `:`, filter on `last_seen`/`first_seen` within 30 days and a high `confidence_level`. Check the column names against the first file you download |
| [Feodo Tracker](https://feodotracker.abuse.ch/downloads/ipblocklist.txt) | Botnet C2 IPs | Yes, alongside ThreatFox | Very few false positives, but only 4 IPs today (the "recommended" list has 0). Most of the current `main.txt` comes from here |
| [URLhaus](https://urlhaus.abuse.ch/api/) (abuse.ch) | Malware download URLs | Optional | Same Auth-Key (`https://urlhaus-api.abuse.ch/v2/files/exports/<KEY>/recent.csv`). Keep only rows whose host is an IP and whose status is `online`. Its domain rows are dropped anyway |
| [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) | Netblocks run entirely by criminals | Later | Very low false positives, but the entries are CIDR ranges, so it needs the client change for ranges |
| [C2-Tracker](https://github.com/montysecurity/C2-Tracker) | Cobalt Strike, Sliver, etc. C2 servers found through Shodan | Worth a look | The repo exists, but `data/all.txt` returned 404. Find the current file path |
| [SSLBL IP list](https://sslbl.abuse.ch/blacklist/sslipblacklist.txt) | C2 found by their SSL certificates | No | Frozen since January 2025 |
| [ET compromised-ips](https://rules.emergingthreats.net/blockrules/compromised-ips.txt), [CINS Army](https://cinsscore.com/list/ci-badguys.txt), blocklist.de | Compromised hosts, scanners, brute-forcers | No | Attacker lists, not C2 lists. Too noisy for `main` (see Decisions) |

Keep the abuse.ch Auth-Key on the server only. Clients download `main.txt` and never contact abuse.ch.

## Build job

A cron job (every few hours is plenty, since abuse.ch updates every few minutes but clients refresh far less often):

1. Download each source and keep the IP and `last_seen` per entry.
2. Reduce `ip:port` and IP-hosted URLs to the bare IP. Drop domains, CIDRs and anything older than 30 days.
3. Drop private, loopback, link-local, multicast and reserved addresses (Python's `ipaddress`: `not ip.is_global`). The client only drops loopback, unspecified and multicast, so a `10.x` entry would flag every LAN on a client.
4. Dedupe, sort, and write one IP per line with a header comment (`# Built <time> from ThreatFox, Feodo`). Sorting keeps the file identical when nothing changed, so the ETag stays the same and clients get 304s.
5. **Sanity check before uploading.** Refuse to publish if the new list is empty or has shrunk by more than half since the last publish (a broken source shouldn't empty everyone's feed), and alert yourself.
6. Gzip and upload with the command above.

## YARA rules

YARA rules are their own tool in Menoa, next to ClamAV: `menoa yara`, with feeds in `[yara_feeds]` in the config. Clients run them with [YARA-X](https://virustotal.github.io/yara-x/) in a separate process ([yara_utils.py](../menoa/utils/yara_utils.py)), on their own (`menoa yara scan`, the GUI's YARA buttons) or alongside clamscan (`menoa scan`, the GUI's main buttons). Matches show up as `YARA.<rule name> FOUND`, with the same exit codes as ClamAV detections. Clients add a feed with `menoa yara add --index menoa --name ... --description ... --url .../menoa.yar` and download it with `menoa yara reload`.

Why YARA-X and not ClamAV's own YARA support (measured with ClamAV 1.4.4):
- ClamAV skips modules (`pe`, `elf`, `dotnet`, `math`), `uint16be`/`uint32be` and single-byte hex patterns.
- A single long string overflows ClamAV's lexer, and every rule after it is dropped without an error. That's why ClamAV loaded only 3,048 of YARA Forge extended's 10,787 rules.
- YARA-X 1.22 compiles every rule in YARA Forge core and full.

How clients handle a feed:
- A rule YARA-X can't compile is left out, and the rest of its file still loads.
- Two feeds can use the same rule name.
- A feed that loads 0 rules (like an HTML error page saved as `menoa.yar`) is reported as a scan problem, not skipped quietly.
- Files over 100 MB are skipped, the same limit as clamscan's default.

### Source: YARA Forge

[YARA Forge](https://github.com/YARAHQ/yara-forge) merges about 40 public rule repos (signature-base, ReversingLabs, Elastic and others), quality-checks them, and publishes three packages on GitHub releases: `https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-<core|extended|full>.zip`. Measured on 2026-10-24, using the 2026-10-17 release:

| Package | Rules | YARA-X compile time | ClamAV false positives in `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu` (5.6 GB) |
|---|---|---|---|
| core | 5,132 | 1.3 s | 0 |
| extended | 10,787 | 3.8 s | 0 |
| full | 12,428 | 4.2 s | 0 |

The false-positive column was measured with ClamAV's parser, so it only covers the rules ClamAV could load. Run it again with YARA-X before choosing extended or full.

**Scan time:** a real `menoa clam scan /usr/bin` (2,164 files) took 72.7 s with ClamAV alone, and 72.0 s with YARA Forge core added. YARA-X runs alongside clamscan and finished first.

**Hack tool rules.** With every rule loading, core flagged `/usr/bin/nping` (nmap's packet tool) as `YARA.SEKOIA_Tool_Nping_Strings`. About 580 core rules detect legitimate offensive or admin tools by name (`*_Tool_*`, `*_Hacktool_*`, `*_HKTL_*`). On a machine with nmap or CTF tools, they'd fire on files the user installed on purpose. Recommendation: leave them out of `menoa.yar` in the build job, and publish them as an optional second feed (`menoa-tools.yar`) for people who want to know about tools on their machine. Decide before the first publish.

Start with **core**, the package YARA Forge recommends for low false positives. Most of the extra rules in full use the `pe` module, which only matters for Windows files. Only 21 rules in full use `elf`.

### Build job

1. Download the YARA Forge package.
2. **Compile it** with `yara_x.Compiler()` with `ignore_invalid_rules(True)`, the way clients do, and log `compiler.ignored_rules()`. Optionally drop the ignored rules so clients don't compile them on every scan.
3. Move the hack tool rules (see above) into `menoa-tools.yar`, or drop them.
4. Write `menoa.yar` with a header comment (`// Built <time> from YARA Forge core <release>`).
5. **Sanity check:** refuse to publish if the rule count is 0 or has fallen by more than half since the last publish. Also scan known-clean folders (e.g. `/usr/bin` on the build server) with the compiled rules, and refuse to publish on any hit.
6. Gzip and upload like `main.txt` (`--acl-public`, `Content-Encoding: gzip`, `--mime-type=text/plain`).

YARA Forge releases about weekly, so build weekly. A new release means every client downloads the whole file once, about 1.5 MB gzipped for core. Otherwise clients get a 304.

## Still open

- **Clients don't refresh on their own.** `feed_update_delay` is unused and nothing runs `menoa network reload` on a schedule. Until the background clock (README roadmap) exists, clients only see a new `main.txt` when they reload by hand.
- **Ranges.** Decide whether the client should support CIDR, for Spamhaus DROP.
- **YARA in the default config.** Once `menoa.yar` is published, add a `[yara_feeds.menoa]` entry to the default config so new installs get it (existing installs would need `menoa yara add`). Publish first: `menoa init` and `menoa yara reload` download every YARA feed and report an error if one is missing on the server. Until a YARA feed exists, combined scans (`menoa scan`, the GUI's main buttons) run ClamAV alone and say so.
