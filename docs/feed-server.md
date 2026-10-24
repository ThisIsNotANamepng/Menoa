# Building and publishing Menoa's feeds

Notes for whoever builds the server side: what clients expect, what was decided, and which sources to use.

## What the server publishes

| Feed | Built by the server? | Where clients get it |
|---|---|---|
| Network (`main.txt`) | Yes | `https://menoa-feeds.us-ord-1.linodeobjects.com/network/main.txt` (`[network_feeds.main]` in the default config) |
| ClamAV signatures | No | Straight from `database.clamav.net` through cvdupdate on the client |
| Process model | No | Ships inside the Menoa package, pinned by `BUILTIN_MODEL_SHA256` in [process_utils.py](../menoa/utils/process_utils.py). A new model means a new Menoa release |

So for now the server's only job is `main.txt`.

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

## Still open

- **Clients don't refresh on their own.** `feed_update_delay` is unused and nothing runs `menoa network reload` on a schedule. Until the background clock (README roadmap) exists, clients only see a new `main.txt` when they reload by hand.
- **Ranges.** Decide whether the client should support CIDR, for Spamhaus DROP.
