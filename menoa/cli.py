"""
CLI interface for Menoa

Scan
- Scan with ClamAV and YARA at once

Clam
- Basic/Full/Custom Scan
- Reload feed from source
- Add/remove feed
- See current feeds (main.cvd, daily.cvd, any custom feeds)
- Set scan delay
- Get scan delay
- Toggle background on/off

YARA
- Basic/Full/Custom Scan
- Reload feeds from source
- Add/remove feed
- See current feeds
- Set/get scan and feed update delay
- Toggle background on/off

Network
- Scan
- Reload current feed
- Add/remove feed
- See current feed
- Set scan delay
- Get scan delay
- Toggle background on/off

Process
- Scan
- Set detection threshold
- Get detection threshold
- Add/remove feed
- See current feed
- Toggle background on/off

=On-device personalized learning
- Toggle on/off
- More settings here as its developed

Attestation
- Get current delay
- Set delay
- Get current status (what packages are tracked, when were they changed, etc)
- Toggle on/off

Commands
- Interpret a bash line
- Interpret a bash file
"""

import sys
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from menoa.utils.utils import initialize, rewrite, feeds_by_engine, FEED_LEVELS
import click
from rich.console import Console
from pathlib import Path
from tqdm import tqdm
from rich.table import Table
from rich import box

import menoa.utils.attestation_utils as attestation_utils
# The other tools' utils are imported inside the commands that use them, so `menoa --help` doesn't load the process model's libraries
import menoa.utils.script_utils as script_utils

console = Console()
err_console = Console(stderr=True)  # Warnings, so they stay out of piped output

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.6.0", prog_name="Menoa")
def cli() -> None:
    """
    The CLI frontend for Menoa. See menoa.org/docs more information 
    """
    pass


@cli.group()
def clam() -> None:
    """
    ClamAV antivirus related commands
    """
    pass

ENGINE_NAMES = {"clam": "ClamAV", "yara": "YARA"}

def feed_options(command: Callable) -> Callable:
    """
    Adds --feed and --level to a scan command
    """
    command = click.option('--level', type=click.Choice(FEED_LEVELS), help="Only feeds up to this level: quick feeds are in every level, deep feeds only in deep")(command)
    return click.option('--feed', 'feeds', multiple=True, help="Only scan with this feed, a feed index or a path to a file. Repeat it for more")(command)

def pick_feeds(engines: Tuple[str, ...], feeds: Sequence[str], level: Optional[str]) -> Dict[str, List[str]]:
    """
    Which feeds each engine scans with, {engine: [names]}. A scan with both engines leaves out one that ends up with no feeds
    Exits 2 if a feed is unknown, or nothing is left to scan with
    """
    import menoa.utils.yara_utils as yara_utils

    try:
        picked = {engine: names for engine, names in feeds_by_engine(engines, feeds, level).items() if names}
    except Exception as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(2)

    if len(engines) > 1 and len(picked) == 1:
        missing, running = [ENGINE_NAMES[e] for e in engines if e not in picked][0], ENGINE_NAMES[next(iter(picked))]
        reason = " matching --feed" if feeds else (f" at level {level}" if level else "")
        hint = " (add one with `menoa yara add`)" if missing == "YARA" and not yara_utils.list_feeds() else ""
        err_console.print(f"[yellow]No {missing} feeds{reason}, scanning with {running} only{hint}[/yellow]")
    if not picked:
        names = " or ".join(ENGINE_NAMES[e] for e in engines)
        hint = ", add one with `menoa yara add`" if engines == ("yara",) and not yara_utils.list_feeds() else ""
        err_console.print(f"[red]No {names} feeds to scan with" + (f" at level {level}" if level else "") + f"{hint}[/red]")
        sys.exit(2)
    return picked

def scan(path: str, quiet: bool = False, engines: Tuple[str, ...] = ("clam",), feeds: Sequence[str] = (), level: Optional[str] = None) -> None:
    """
    Scans path with ClamAV, YARA, or both at once, then exits like clamscan: 0 clean, 1 malware found, 2 scan failed
    feeds and level pick the feeds to scan with (see utils.select_feeds), all of them without either
    """
    import threading
    import menoa.utils.clam_utils as clam_utils
    import menoa.utils.yara_utils as yara_utils

    picked = pick_feeds(engines, feeds, level)
    engines = tuple(picked)

    # Still scans with old signatures, they catch less but more than nothing. A missing database fails the scan below
    if "clam" in engines:
        state, text = clam_utils.database_freshness()
        if not quiet and state in ("outdated", "critical"):
            color = "red" if state == "critical" else "yellow"
            err_console.print(f"[{color}]Warning: {text}, run `menoa clam reload` to update them (--quiet hides this)[/{color}]")

    both = len(engines) > 1
    counters = {"clam": clam_utils.get_scan_total, "yara": yara_utils.count_files}
    console.print("[yellow]Counting total files...  [/yellow]", end='')
    totals = {engine: counters[engine](path) for engine in engines}
    print(", ".join(f"{ENGINE_NAMES[e]} {totals[e]}" for e in engines) if both else totals[engines[0]])

    for engine in engines:
        console.print(f"[yellow]{ENGINE_NAMES[engine]} feeds: {', '.join(picked[engine]) or 'none'}[/yellow]")

    results = {}

    def run(engine: str, position: int) -> None:
        stream = {"clam": clam_utils.scan_path_streaming, "yara": yara_utils.scan_path_streaming}[engine]
        label = f"{ENGINE_NAMES[engine]}: " if both else ""
        result_list = results[engine] = {"infected": [], "problems": [], "summary": {}, "error": None}
        progress = None
        stage_bar = None

        def on_progress(stage: str, done: float, total: float) -> None:
            # clamscan's totals are running estimates that change as it opens each database, so show its percentage
            nonlocal stage_bar
            if not total:  # Nothing to measure, like YARA-X compiling its rules
                tqdm.write(f"{label}{stage}...")
                return
            if stage_bar is None or stage_bar.desc != label + stage:
                if stage_bar:
                    stage_bar.close()
                stage_bar = tqdm(desc=label + stage, total=100, position=position, bar_format="{desc}: {percentage:3.0f}%|{bar}| {elapsed}")
            stage_bar.n = min(100, round(done / total * 100))
            stage_bar.refresh()

        try:
            for file, result in stream(path, on_progress, result_list["summary"].update, picked[engine] if feeds else None, level):
                kind = clam_utils.result_kind(file, result)
                if kind == "infected":
                    result_list["infected"].append(f"{file} {result}")
                elif kind == "error":
                    result_list["problems"].append(f"{label}{file}: {result}" if file else label + result)

                if progress is None:  # Created once the signatures are loaded, so it doesn't sit at 0% meanwhile
                    if stage_bar:
                        stage_bar.close()
                    progress = tqdm(desc=f"{label}Scanning files", unit="file", total=totals[engine], position=position)

                if file:
                    progress.update(1)
        except Exception as e:
            result_list["error"] = e
        finally:
            for bar in (stage_bar, progress):
                if bar:
                    bar.close()

    if both:
        threads = [threading.Thread(target=run, args=(engine, i), daemon=True) for i, engine in enumerate(engines)]
        for thread in threads:
            thread.start()
        for thread in threads:
            while thread.is_alive():
                thread.join(0.2)  # Short waits so Ctrl-C still stops the scan
    else:
        run(engines[0], 0)

    for engine in engines:
        label = f"{ENGINE_NAMES[engine]}: " if both else ""
        result_list = results[engine]
        if result_list["error"]:
            console.print(f"[red]{label}Scan failed, files were NOT checked: {result_list['error']}[/red]")
            continue
        summary = result_list["summary"]
        rules = f"{int(summary.get('Known viruses', 0)):,} signatures" if engine == "clam" else f"{int(summary.get('YARA rules', 0)):,} YARA rules"
        console.print(f"{label}Scanned {summary.get('Scanned files', '?')} files with {rules} in {summary.get('Time', '?').split(' (')[0]}")

    infected = [line for engine in engines for line in results[engine]["infected"]]
    problems = [line for engine in engines for line in results[engine]["problems"]]

    if problems:
        # A full scan can hit thousands of unreadable files, show the first few
        console.print(f"[yellow]{len(problems)} item(s) couldn't be scanned:[/yellow]")
        for p in problems[:20]:
            print(" ", p)
        if len(problems) > 20:
            print(f"  ...and {len(problems) - 20} more")

    # Malware found matters more than one engine failing, so it decides the exit code first
    if infected:
        console.print("[red]Malware found[/red]")
        for line in infected:
            print(line)
        sys.exit(1)
    if any(results[engine]["error"] for engine in engines):
        sys.exit(2)
    console.print("[green]No malware found![/green]")

@clam.command(name="quick")
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about outdated malware signatures")
@feed_options
def clam_quick_scan(quiet: bool, feeds: Tuple[str, ...], level: Optional[str]) -> None:
    """
    Scans places in which malware is most often found (~/Downloads)
    """

    console.print("[blue]Starting quick scan[/blue]")
    scan(str(Path.home()) + "/Downloads/", quiet, feeds=feeds, level=level)

@clam.command(name="full")
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about outdated malware signatures")
@feed_options
def clam_full_scan(quiet: bool, feeds: Tuple[str, ...], level: Optional[str]) -> None:
    """
    Scans the whole system from /
    """

    console.print("[blue]Starting full system scan from /[/blue]")
    scan("/", quiet, feeds=feeds, level=level)


@clam.command(name="scan")
@click.argument('path', type=str)
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about outdated malware signatures")
@feed_options
def clam_custom_scan(path: str, quiet: bool, feeds: Tuple[str, ...], level: Optional[str]) -> None:
    """
    Perform a custom Clam scan using a given file/dir path
    """

    console.print(f"[blue]Starting scan from: {path}[/blue]")
    scan(path, quiet, feeds=feeds, level=level)

@clam.command(name="status")
def clam_status() -> None:
    """
    Shows the malware signature version and age. Exits 1 if they're outdated, 2 if they're missing or unreadable
    """
    import menoa.utils.clam_utils as clam_utils

    version, built = clam_utils.get_database_version()
    state, text = clam_utils.database_freshness()
    color = {"fresh": "green", "outdated": "yellow"}.get(state, "red")

    print(f"Database version: {version}, built {built}")
    console.print(f"[{color}]{text}[/{color}]")
    if state in ("outdated", "critical"):
        console.print(f"[{color}]Run `menoa clam reload` to update them[/{color}]")
        sys.exit(1)
    if state != "fresh":
        console.print("[red]Run `menoa clam reload` to download them[/red]")
        sys.exit(2)

@clam.command(name="reload")
@click.argument('feed', type=str, required=False)
def clam_reload_feed(feed: Optional[str] = None) -> None:
    """
    Reload Clam feed from source. If a name or a url is passed then just reload that feed, else reload all
    """
    import menoa.utils.clam_utils as clam_utils

    if feed:
        console.print("[yellow]Reloading feed...[/yellow]")
        clam_utils.update_feed(feed)
        console.print("[green]Feed reloaded[/green]")
    else:
        console.print("[yellow]Reloading feeds...[/yellow]")
        clam_utils.update_all_feeds()
        console.print("[green]Feeds reloaded[/green]")   

@clam.command(name="add")
@click.option('--index', type=str, required=True)
@click.option('--name', type=str, required=True)
@click.option('--url', type=str, required=True)
@click.option('--description', type=str, required=True)
@click.option('--local-path', type=str, required=True)
@click.option('--centralize', is_flag=True, default=False)
@click.option('--level', type=click.Choice(FEED_LEVELS), default=None, help="Which scan levels use it (quick: all of them, the default; standard; deep: only deep scans)")
def clam_add_feed(index: str, name: str, url: str, description: str, local_path: str, centralize: bool, level: Optional[str]) -> None:
    """
    Add a new Clam feed
    """
    import menoa.utils.clam_utils as clam_utils

    clam_utils.add_feed(index, name, url, description, local_path, centralize, level)
    console.print(f"[green]Added {name}![/green]")

@clam.command(name="remove")
@click.argument('index', type=str, required=True)
def clam_remove_feed(index: str) -> None:
    """
    Remove an existing Clam feed
    """
    import menoa.utils.clam_utils as clam_utils

    clam_utils.remove_feed(index)
    console.print(f"[green]{index} removed![/green]")

@clam.command(name="list")
def clam_list_feeds() -> None:
    """
    Print a table of the current Clam feeds
    """
    ## TODO: Add non-verbose option 
    import menoa.utils.clam_utils as clam_utils

    table = Table(title="ClamAV Signature Feeds", box=box.ROUNDED)

    table.add_column("Index", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("Description", style="magenta")
    table.add_column("Upstream URL", style="magenta")
    table.add_column("Local Storage", style="magenta")
    table.add_column("Last Refreshed", style="magenta")
    table.add_column("Level", style="magenta")

    feeds = clam_utils.list_feeds()

    for i in feeds:
        table.add_row(i, feeds[i]["name"], feeds[i]["description"], feeds[i]["url"], feeds[i]["local_path"], str(feeds[i]["last_refreshed"]), feeds[i].get("level", "quick"))

    console.print(table)

@clam.command(name="delay")
@click.option('--update', required=False, is_flag=True)
@click.argument('seconds', type=click.IntRange(min=0), required=False)
def clam_set_delay(update: bool, seconds: Optional[int] = None) -> None:
    """
    Set/get scan or feed update delay (in seconds) for Clam. If no delay is passed, prints the delay and exits
    """
    import menoa.utils.clam_utils as clam_utils

    if seconds is None and update:
        console.print(f"[green]Feed update delay: {clam_utils.get_delay()['feed_update_delay']}[/green]")
    elif seconds is None:
        console.print(f"[green]Scan delay: {clam_utils.get_delay()['scan_delay']}[/green]")
    elif update:
        clam_utils.set_feed_update_delay(seconds)
        console.print(f"[green]Set feed update delay to {seconds}")
    else:
        clam_utils.set_scanning_delay(seconds)
        console.print(f"[green]Set scanning delay to {seconds}")

@clam.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def clam_toggle_background(on: bool, off: bool) -> None:
    """
    Toggle Clam background scanning on/off
    """
    import menoa.utils.clam_utils as clam_utils

    if on:
        clam_utils.toggle(True)
        console.print("[green]Background scan toggled on[/green]")
    elif off:
        clam_utils.toggle(False)
        console.print("[green]Background scan toggled off[/green]")
    else:
        console.print(f"[green]Background scan toggled {clam_utils.toggle()}[/green]")


@cli.command(name="scan")
@click.argument('path', type=str, required=False)
@click.option('--quick', is_flag=True, help="Scan ~/Downloads, where malware is most often found")
@click.option('--full', is_flag=True, help="Scan the whole system from /")
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about outdated malware signatures")
@feed_options
def scan_command(path: Optional[str], quick: bool, full: bool, quiet: bool, feeds: Tuple[str, ...], level: Optional[str]) -> None:
    """
    Scans a path with ClamAV and YARA rules at once (one engine alone if the other has no feeds to use). Exits 0 if clean, 1 if malware is found, 2 if a scan failed
    """
    if [bool(path), quick, full].count(True) != 1:
        raise click.UsageError("Pass a path, --quick or --full")

    target = path or (str(Path.home()) + "/Downloads/" if quick else "/")
    console.print(f"[blue]Starting scan from: {target}[/blue]")
    scan(target, quiet, ("clam", "yara"), feeds, level)


@cli.group()
def yara() -> None:
    """
    YARA rule scanning (with YARA-X) related commands
    """
    pass

@yara.command(name="scan")
@click.argument('path', type=str)
@feed_options
def yara_custom_scan(path: str, feeds: Tuple[str, ...], level: Optional[str]) -> None:
    """
    Scans a file/dir path with the YARA feeds
    """
    console.print(f"[blue]Starting YARA scan from: {path}[/blue]")
    scan(path, engines=("yara",), feeds=feeds, level=level)

@yara.command(name="quick")
@feed_options
def yara_quick_scan(feeds: Tuple[str, ...], level: Optional[str]) -> None:
    """
    Scans places in which malware is most often found (~/Downloads) with the YARA feeds
    """
    console.print("[blue]Starting quick YARA scan[/blue]")
    scan(str(Path.home()) + "/Downloads/", engines=("yara",), feeds=feeds, level=level)

@yara.command(name="full")
@feed_options
def yara_full_scan(feeds: Tuple[str, ...], level: Optional[str]) -> None:
    """
    Scans the whole system from / with the YARA feeds
    """
    console.print("[blue]Starting full system YARA scan from /[/blue]")
    scan("/", engines=("yara",), feeds=feeds, level=level)

@yara.command(name="reload")
@click.argument('feed', type=str, required=False)
def yara_reload_feed(feed: Optional[str] = None) -> None:
    """
    Downloads YARA feeds again. If an index is passed just that feed, else all of them
    """
    import menoa.utils.yara_utils as yara_utils

    if feed:
        console.print("[yellow]Reloading feed...[/yellow]")
        yara_utils.update_feed(feed)
        console.print("[green]Feed reloaded[/green]")
        return

    console.print("[yellow]Reloading feeds...[/yellow]")
    failures = yara_utils.update_all_feeds()
    for failure in failures:
        err_console.print(f"[red]{failure}[/red]")
    if failures:
        sys.exit(1)
    console.print("[green]Feeds reloaded[/green]")

@yara.command(name="add")
@click.option('--index', type=str, required=True)
@click.option('--name', type=str, required=True)
@click.option('--description', type=str, required=True)
@click.option('--url', type=str, default="", help="Where to download the rule file from")
@click.option('--local-path', type=str, default=None, help="Where the rule file is kept, a file of your own if there's no --url (default ~/.menoa/feeds/yara/<index>.yar)")
@click.option('--level', type=click.Choice(FEED_LEVELS), default=None, help="Which scan levels use it (quick: all of them, the default; standard; deep: only deep scans)")
def yara_add_feed(index: str, name: str, description: str, url: str, local_path: Optional[str], level: Optional[str]) -> None:
    """
    Add a YARA rule feed
    """
    import menoa.utils.yara_utils as yara_utils

    yara_utils.add_feed(index, name, url, description, local_path, level)
    console.print(f"[green]Added {name}![/green]" + (f" Run `menoa yara reload {index}` to download it" if url else ""))

@yara.command(name="remove")
@click.argument('index', type=str, required=True)
def yara_remove_feed(index: str) -> None:
    """
    Remove a YARA feed
    """
    import menoa.utils.yara_utils as yara_utils

    yara_utils.remove_feed(index)
    console.print(f"[green]{index} removed![/green]")

@yara.command(name="list")
def yara_list_feeds() -> None:
    """
    Print a table of the current YARA feeds
    """
    import menoa.utils.yara_utils as yara_utils

    table = Table(title="YARA Rule Feeds", box=box.ROUNDED)
    for column in ("Index", "Name", "Description", "Upstream URL", "Local Storage", "Last Refreshed", "Level"):
        table.add_column(column, justify="right" if column == "Index" else "left", style="cyan" if column == "Index" else "magenta", no_wrap=column == "Index")

    for index, feed in yara_utils.list_feeds().items():
        table.add_row(index, feed["name"], feed["description"], feed["url"], feed["local_path"], str(feed["last_refreshed"]), feed.get("level", "quick"))

    console.print(table)

@yara.command(name="delay")
@click.option('--update', required=False, is_flag=True)
@click.argument('seconds', type=click.IntRange(min=0), required=False)
def yara_set_delay(update: bool, seconds: Optional[int] = None) -> None:
    """
    Set/get scan or feed update delay (in seconds) for YARA. If no delay is passed, prints the delay and exits
    """
    import menoa.utils.yara_utils as yara_utils

    if seconds is None and update:
        console.print(f"[green]Feed update delay: {yara_utils.get_delay()['feed_update_delay']}[/green]")
    elif seconds is None:
        console.print(f"[green]Scan delay: {yara_utils.get_delay()['scan_delay']}[/green]")
    elif update:
        yara_utils.set_feed_update_delay(seconds)
        console.print(f"[green]Set feed update delay to {seconds}")
    else:
        yara_utils.set_scanning_delay(seconds)
        console.print(f"[green]Set scanning delay to {seconds}")

@yara.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def yara_toggle_background(on: bool, off: bool) -> None:
    """
    Toggle YARA background scanning on/off
    """
    import menoa.utils.yara_utils as yara_utils

    if on or off:
        yara_utils.toggle(on)
        console.print(f"[green]Background scan toggled {'on' if on else 'off'}[/green]")
    else:
        console.print(f"[green]Background scan toggled {'on' if yara_utils.toggle() else 'off'}[/green]")


@cli.group()
def network() -> None:
    """
    Network scanning related commands
    """
    pass

@network.command(name="scan")
def network_scan() -> None:
    """
    Checks current connections against the network feeds. Exits 0 if none are malicious, 1 if some are, 2 if no feed is downloaded
    """
    import menoa.utils.network_utils as network_utils

    for index in network_utils.missing_feeds():
        err_console.print(f"[yellow]Network feed {index} hasn't been downloaded, run `menoa network reload {index}`[/yellow]")

    try:
        results = network_utils.connections_check()
    except Exception as e:
        console.print(f"[red]Scan failed, connections were NOT checked: {e}[/red]")
        sys.exit(2)

    malicious = [r for r in results if r["malicious"]]
    if not malicious:
        console.print(f"[green]No malicious connections ({len(results)} checked)[/green]")
        return

    console.print(f"[red]{len(malicious)} malicious connection(s) found![/red]")
    table = Table(box=box.ROUNDED)
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("Process", style="magenta")
    table.add_column("Remote address", style="red")
    for r in malicious:
        table.add_row(str(r["pid"] or "-"), r["process"] or "(unknown, run as root to see)", r["remote"])
    console.print(table)
    sys.exit(1)

@network.command(name="reload")
@click.argument('feed', type=str, required=False)
def network_reload_feed(feed: Optional[str] = None) -> None:
    """
    Reload network feed(s) from source
    """
    import menoa.utils.network_utils as network_utils
    
    if feed:
        console.print(f"[yellow]Reloading {feed}...[/yellow]")
        try:
            count = network_utils.update_feed(feed)
        except Exception as e:
            console.print(f"[red]Reloading {feed} failed: {e}[/red]")
            sys.exit(1)
        console.print(f"[green]{feed} reloaded, {count} IPs[/green]")
    else:
        console.print("[yellow]Reloading feeds...[/yellow]")
        # update_all_feeds() already printed each failure
        if network_utils.update_all_feeds():
            console.print("[red]Some feeds failed to reload[/red]")
            sys.exit(1)
        console.print("[green]Feeds reloaded[/green]")

@network.command(name="add")
@click.option('--index', type=str, required=True)
@click.option('--name', type=str, required=True)
@click.option('--description', type=str, required=True)
@click.option('--format', 'feed_format', type=click.Choice(["plain", "csv", "misp", "command"]), required=True)
@click.option('--url', type=str, help="Feed url or local path (plain, csv, misp)")
@click.option('--column', type=str, help="Header name or 0-based column number holding the IP/URL (csv)")
@click.option('--command', type=str, help="Command that prints one indicator per line (command)")
@click.option('--api-key-env', type=str, help="Environment variable holding the API key (misp)")
def network_add_feed(index: str, name: str, description: str, feed_format: str, url: Optional[str], column: Optional[str],
                     command: Optional[str], api_key_env: Optional[str]) -> None:
    """
    Add a new network feed and download it
    """
    import menoa.utils.network_utils as network_utils

    if column is not None and column.isdigit():
        column = int(column)

    network_utils.add_feed(index, name, description, feed_format, url, column, command, api_key_env)
    console.print(f"[green]Added {name}![/green]")

    console.print(f"[yellow]Downloading {index}...[/yellow]")
    try:
        console.print(f"[green]{network_utils.update_feed(index)} IPs loaded[/green]")
    except Exception as e:
        console.print(f"[red]Download failed: {e}[/red]")

@network.command(name="remove")
@click.argument('index', type=str, required=True)
def network_remove_feed(index: str) -> None:
    """
    Remove an existing network feed
    """
    import menoa.utils.network_utils as network_utils
    
    console.print(f"[yellow]Removing network feed: {index}...[/yellow]")
    network_utils.remove_feed(index)
    console.print("[green]Network feed removed.[/green]")

@network.command(name="feeds")
def network_list_feeds() -> None:
    """
    Show current network feeds
    """
    ## TODO: Add non-verbose option 
    import menoa.utils.network_utils as network_utils
    
    console.print("[yellow]Fetching network feeds...[/yellow]")
    table = Table(title="Network Endpoint Feeds", box=box.ROUNDED)

    table.add_column("Index", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("Description", style="magenta")
    table.add_column("Format", style="magenta")
    table.add_column("Source", style="magenta")
    table.add_column("Last Refreshed", style="magenta")

    feeds = network_utils.list_feeds()

    for i in feeds:
        f = feeds[i]
        table.add_row(i, f.get("name", ""), f.get("description", ""), str(f.get("format")), f.get("url") or f.get("command", ""), str(f.get("last_refreshed")))

    console.print(table)
    console.print("[green]Showing feeds[/green]")

@network.command(name="delay")
@click.option('--update', required=False, is_flag=True)
@click.argument('seconds', type=click.IntRange(min=0), required=False)
def network_set_delay(update: bool, seconds: Optional[int] = None) -> None:
    """
    Set/get network scan or feed update delay (in seconds). If no delay is passed, prints the delay and exits
    """
    import menoa.utils.network_utils as network_utils
    
    if seconds is None and update:
        console.print(f"[green]Feed update delay: {network_utils.get_delay()['feed_update_delay']}[/green]")
    elif seconds is None:
        console.print(f"[green]Scan delay: {network_utils.get_delay()['scan_delay']}[/green]")
    elif update:
        network_utils.set_feed_update_delay(seconds)
        console.print(f"[green]Set feed update delay to {seconds}")
    else:
        network_utils.set_scanning_delay(seconds)
        console.print(f"[green]Set scanning delay to {seconds}")

@network.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def network_toggle_background_on(on: bool, off: bool) -> None:
    """
    Toggle network background scanning on/off
    """
    import menoa.utils.network_utils as network_utils

    if on:
        network_utils.toggle(True)
        console.print("[green]Background scan toggled on[/green]")
    elif off:
        network_utils.toggle(False)
        console.print("[green]Background scan toggled off[/green]")
    else:
        console.print(f"[green]Background scan toggled {network_utils.toggle()}[/green]")


@cli.group()
def process() -> None:
    """
    Process scanning related commands
    """
    pass

@process.command(name="scan")
@click.option('--threshold', type=float, required=False, help="Defaults to the threshold in the config")
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about using your own unsigned model")
def process_scan(threshold: Optional[float] = None, quiet: bool = False) -> None:
    """
    Scans running processes with given threshold
    """

    import menoa.utils.process_utils as process_utils

    # Someone who can edit config.toml could swap in their own model, so a model that isn't checked is always pointed out
    settings = process_utils.get_model_settings()
    if not quiet and process_utils.is_unsigned_model(settings):
        err_console.print(f"[yellow]Warning: using your own unsigned process model ({settings['model_url']}), make sure it's the one you added (--quiet hides this)[/yellow]")

    if threshold is None:
        threshold = process_utils.get_process_threshold()

    results = process_utils.predict(threshold)

    
    if not "Malicious" in results[1]:
        console.print("[green]No malicious processes found[/green]")

    else:
        console.print("[red]Malicious processes found![/red]")
        table = Table(title="Process Scan Results", box=box.ROUNDED)

        table.add_column("PID", justify="right", style="cyan", no_wrap=True)
        table.add_column("Prediction", style="magenta")
        table.add_column("Confidence", style="magenta")

        for pid, pred, conf in zip(results[0], results[1], results[2]):
            if pred == "Malicious" and conf >= threshold:
                table.add_row(str(pid), pred, f"{conf:.4f}")

        console.print(table)

@process.command(name="delay")
@click.argument('seconds', type=click.FloatRange(min=0), required=False)
def process_set_delay(seconds: Optional[float] = None) -> None:
    """
    Set/get process scan delay (in seconds). If no delay is passed, prints the delay and exits
    """

    import menoa.utils.process_utils as process_utils

    if seconds is None:
        console.print(f"[green]Delay: {process_utils.get_scanning_delay()}[/green]")
    else:
        process_utils.set_scanning_delay(seconds)
        console.print(f"[green]Process scan delay set to {seconds} seconds[/green]")

@process.command(name="threshold")
@click.argument('threshold', type=click.FloatRange(0, 1), required=False)
def process_get_threshold(threshold: Optional[float] = None) -> None:
    """
    Set/get process scan detection threshold (0 to 1). If no threshold is passed, prints the threshold and exits
    """

    import menoa.utils.process_utils as process_utils

    if threshold is None:
        console.print(f"[green]Threshold: {process_utils.get_process_threshold()}[/green]")
    else:
        process_utils.set_process_threshold(threshold)
        console.print(f"[green]Process scan threshold set to {threshold}[/green]")

@process.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def process_toggle_background_on(on: bool, off: bool) -> None:
    """
    Toggle process background scanning on/off
    """
    import menoa.utils.process_utils as process_utils

    if on:
        process_utils.toggle(True)
        console.print("[green]Background scan toggled on[/green]")
    elif off:
        process_utils.toggle(False)
        console.print("[green]Background scan toggled off[/green]")
    else:
        console.print(f"[green]Background scan toggled {process_utils.toggle()}[/green]")

@process.command(name="model")
@click.argument('source', required=False)
@click.option('--public-key', default="", help="Only load the model if it's signed with this key (its signature is SOURCE.sig)")
@click.option('--default', 'use_default', is_flag=True, help="Go back to Menoa's model")
def process_model(source: Optional[str], public_key: str, use_default: bool) -> None:
    """
    Uses the process model at SOURCE (a URL or a local path). Without --public-key your own model isn't checked,
    only use models you trust: loading one runs code from it. With no SOURCE, shows the current model
    """
    import menoa.utils.process_utils as process_utils

    if not source and not use_default:
        settings = process_utils.get_model_settings()
        print(f"Model: {settings['model_url'] or 'bundled with Menoa'}")
        try:
            version = process_utils.verify_model(process_utils.MODEL_PATH, process_utils.MODEL_PATH + ".sig", settings)
        except FileNotFoundError:
            console.print("[yellow]Not downloaded yet[/yellow]")
            return
        except Exception as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
        if version is None:
            console.print("[yellow]Your own model, not signature checked[/yellow]")
        elif version == "built-in":
            console.print("[green]Menoa's built-in model[/green]")
        elif process_utils.is_official_model(settings):
            console.print(f"[green]Menoa's model, signed by Menoa, version {version}[/green]")
        else:
            console.print(f"[green]Signed with model_public_key, version {version}[/green]")
        return

    try:
        if use_default:
            process_utils.set_model()
        else:
            process_utils.set_model(source, public_key)
    except Exception as e:
        console.print(f"[red]Model not changed: {e}[/red]")
        sys.exit(1)
    console.print("[green]Process model updated[/green]")

@process.command(name="keygen")
@click.argument('private_key', type=click.Path(dir_okay=False))
def process_keygen(private_key: str) -> None:
    """
    Creates a key for signing process models. Keep PRIVATE_KEY offline, anyone with it can sign models that run on your users' machines
    """
    import menoa.utils.process_utils as process_utils

    try:
        public_key = process_utils.generate_signing_key(private_key)
    except FileExistsError:
        console.print(f"[red]{private_key} already exists, models signed with it would stop loading if it were replaced[/red]")
        sys.exit(1)

    console.print(f"[green]Private key written to {private_key}[/green]")
    print("Put this in the [process] section of ~/.menoa/config.toml (or your users' default config):")
    print(f'model_public_key = "{public_key}"')

@process.command(name="sign")
@click.argument('model', type=click.Path(exists=True, dir_okay=False))
@click.option('--key', 'private_key', required=True, type=click.Path(exists=True, dir_okay=False), help="Private key from `menoa process keygen`")
@click.option('--model-version', type=str, help="Defaults to the version inside the model")
def process_sign(model: str, private_key: str, model_version: Optional[str]) -> None:
    """
    Signs a process model, writing MODEL.sig to publish next to it
    """
    import menoa.utils.process_utils as process_utils

    version = process_utils.sign_model(model, private_key, model_version)
    console.print(f"[green]Signed {model} (version {version}), publish {model}.sig next to it[/green]")

"""
# --------------------
# On-device Personalized Learning Commands
# --------------------
@cli.group(name="ondevice")
def ondevice():
    #On-device personalized learning commands
    pass

@ondevice.command(name="toggle")
def ondevice_toggle():
    
    #Toggle on-device personalized learning on/off.
    
    console.print("[yellow]On-device learning is a work in progress, check back later to use this tool[/yellow]")
    # Implementation
    #console.print("[green]On-device learning toggled.[/green]")
"""

@cli.group()
def attestation() -> None:
    """
    Attestation related commands
    """
    pass

@attestation.command(name="delay")
@click.argument('seconds', type=click.FloatRange(min=0), required=False)
def attestation_set_delay(seconds: Optional[float] = None) -> None:
    """
    Set/get attestation check delay (in seconds). If no delay is passed, prints the delay and exits
    """

    if seconds is None:
        console.print(f"[green]Delay: {attestation_utils.get_scanning_delay()}[/green]")
    else:
        attestation_utils.set_scanning_delay(seconds)
        console.print(f"[green]Attestation check delay set to {seconds} seconds[/green]")

"""
@attestation.command(name="status")
def attest_get_status():

    #Get current attestation status
    
    console.print("[yellow]Fetching attestation status...[/yellow]")
    # Implementation
    console.print(f"Current status: [bold]{status}[/bold]")
"""

@attestation.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def attestation_toggle_background_on(on: bool, off: bool) -> None:
    """
    Toggle attestation background checks on/off
    """

    if on:
        attestation_utils.toggle(True)
        console.print("[green]Background scan toggled on[/green]")
    elif off:
        attestation_utils.toggle(False)
        console.print("[green]Background scan toggled off[/green]")
    else:
        console.print(f"[green]Background scan toggled {attestation_utils.toggle()}[/green]")


@cli.group(name="shell")
def shell() -> None:
    """
    Bash interpreter related commands
    """
    pass

@shell.command(name="explain")
@click.argument('source', type=str)
def shell_interpret_source(source: str) -> None:
    """
    Explains what a bash script (a file path or URL) would do, without running it
    """
    console.print(f"[yellow]Interpreting: {source}[/yellow]")
    if "http://" in source or "https://" in source:
        script = script_utils.load_remote_script(source)
    elif Path(source).exists():
        script = script_utils.load_local_script(source)
    else:
        console.print("[yellow]Error: Source is neither a valid file path nor a URL. Exiting.[/yellow]")
        
    script = script_utils.parse_script(script)
    for i in (script_utils.predict_actions(script)):
        print(i)

@cli.command()
def init() -> None:
    """
    Creates anything missing in ~/.menoa and downloads the feeds
    """
    failures = initialize()
    if failures:
        console.print("[red]Some setup steps failed, run `menoa init` to retry:[/red]\n" + "\n".join(failures))
        sys.exit(1)
    console.print("[green]Menoa is set up[/green]")

@cli.command()
def fix() -> None:
    """
    Deletes ~/.menoa and sets it up again from the defaults, your feeds and settings are lost
    """
    rewrite()

def main() -> None:
    """
    The menoa command's entry point
    """
    cli()

if __name__ == "__main__":
    main()