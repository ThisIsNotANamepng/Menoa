"""
CLI interface for Menoa

Clam
- Basic/Full/Custom Scan
- Reload feed from source
- Add/remove feed
- See current feeds (main.cvd, daily.cvd, any custom feeds)
- Set scan delay
- Get scan delay
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
from menoa.utils.utils import initialize, rewrite
import click
from rich.console import Console
from pathlib import Path
from tqdm import tqdm
from rich.table import Table
from rich import box

import menoa.utils.attestation_utils as attestation_utils
#import menoa.utils.clam_utils as clam_utils
#import menoa.utils.network_utils as network_utils
#import utils.process_utils as process_utils
import menoa.utils.script_utils as script_utils

console = Console()
err_console = Console(stderr=True)  # Warnings, so they stay out of piped output

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.6.0", prog_name="Menoa")
def cli():
    """
    The CLI frontend for Menoa. See menoa.org/docs more information 
    """
    pass


@cli.group()
def clam():
    """ClamAV antivirus related commands"""
    pass

def scan(path, quiet=False):
    import menoa.utils.clam_utils as clam_utils

    # Still scans with old signatures, they catch less but more than nothing. A missing database fails the scan below
    state, text = clam_utils.database_freshness()
    if not quiet and state in ("outdated", "critical"):
        color = "red" if state == "critical" else "yellow"
        err_console.print(f"[{color}]Warning: {text}, run `menoa clam reload` to update them (--quiet hides this)[/{color}]")

    console.print("[yellow]Counting total files...  [/yellow]", end='')
    total_files = clam_utils.get_scan_total(path)
    print(total_files)

    #print(total_files)
    console.print(f"[yellow]Loading signatures from {', '.join(clam_utils.list_feeds())}...[/yellow]", end='')
    progress = None

    first = True

    infected = []
    problems = []

    try:
        for file, result in clam_utils.scan_path_streaming(path):
            kind = clam_utils.result_kind(file, result)
            if kind == "infected":
                infected.append(f"{file} {result}")
            elif kind == "error":
                problems.append(f"{file}: {result}" if file else result)

            if progress is None: # If the progress bar is created before the loop it's hung at 0% while the signatures are loaded into memory
                print()
                progress = tqdm(desc="Scanning files", unit="file", total=total_files)

            if file:
                progress.update(1)
    except Exception as e:
        if progress:
            progress.close()
        console.print(f"[red]Scan failed, files were NOT checked: {e}[/red]")
        sys.exit(2)

    if progress:
        progress.close()

    if problems:
        # A full scan can hit thousands of unreadable files, show the first few
        console.print(f"[yellow]{len(problems)} item(s) couldn't be scanned:[/yellow]")
        for p in problems[:20]:
            print(" ", p)
        if len(problems) > 20:
            print(f"  ...and {len(problems) - 20} more")

    # Exit codes match clamscan: 0 clean, 1 malware found, 2 scan failed
    if len(infected) == 0:
        console.print("[green]No malware found![/green]")
    else:
        console.print("[red]Malware found[/red]")
        for line in infected:
            print(line)
        sys.exit(1)

@clam.command(name="quick")
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about outdated malware signatures")
def clam_quick_scan(quiet):
    """
    Scans places in which malware is most often found (~/Downloads)
    """
    import menoa.utils.clam_utils as clam_utils

    console.print("[blue]Starting quick scan[/blue]")
    scan(str(Path.home()) + "/Downloads/", quiet)

@clam.command(name="full")
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about outdated malware signatures")
def clam_full_scan(quiet):
    """
    Scans the whole system from /
    """
    import menoa.utils.clam_utils as clam_utils

    console.print("[blue]Starting full system scan from /[/blue]")
    scan("/", quiet)


@clam.command(name="scan")
@click.argument('path', type=str)
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about outdated malware signatures")
def clam_custom_scan(path, quiet):
    """
    Perform a custom Clam scan using a given file/dir path
    """
    import menoa.utils.clam_utils as clam_utils

    console.print(f"[blue]Starting scan from: {path}[/blue]")
    scan(path, quiet)

@clam.command(name="status")
def clam_status():
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
def clam_reload_feed(feed=False):
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
def clam_add_feed(index, name, url, description, local_path, centralize):
    """
    Add a new Clam feed.
    """
    import menoa.utils.clam_utils as clam_utils

    clam_utils.add_feed(index, name, url, description, local_path, centralize)
    console.print(f"[green]Added {name}![/green]")

@clam.command(name="remove")
@click.argument('index', type=str, required=True)
def clam_remove_feed(index):
    """
    Remove an existing Clam feed
    """
    import menoa.utils.clam_utils as clam_utils

    clam_utils.remove_feed(index)
    console.print(f"[green]{index} removed![/green]")

@clam.command(name="list")
def clam_list_feeds():
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

    feeds = clam_utils.list_feeds()

    for i in feeds:
        table.add_row(i, feeds[i]["name"], feeds[i]["description"], feeds[i]["url"], feeds[i]["local_path"], str(feeds[i]["last_refreshed"]))

    console.print(table)

@clam.command(name="delay")
@click.option('--update', required=False, is_flag=True)
@click.argument('seconds', type=int, required=False)
def clam_set_delay(update, seconds=False):
    """
    Set/get scan or feed update delay (in seconds) for Clam. If no delay is passed, prints the delay and exits
    """
    import menoa.utils.clam_utils as clam_utils

    if not seconds and update:
        console.print(f"[green]Feed update delay: {clam_utils.get_delay()['feed_update_delay']}[/green]")
    elif not seconds and not update:
        console.print(f"[green]Scan delay: {clam_utils.get_delay()['scan_delay']}[/green]")
    elif seconds and update:
        clam_utils.set_feed_update_delay(seconds)
        console.print(f"[green]Set feed update delay to {seconds}")
    else:
        clam_utils.set_scanning_delay(seconds)
        console.print(f"[green]Set scanning delay to {seconds}")

@clam.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def clam_toggle_background(on, off):
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


@cli.group()
def network():
    """Network scanning related commands"""
    pass

@network.command(name="scan")
def network_scan():
    """
    Scan the current connections against network feeds
    """
    import menoa.utils.network_utils as network_utils

    console.print("[yellow]Starting network scan...[/yellow]")
    network_utils.connections_check()
    console.print("[green]Network scan completed.[/green]")

@network.command(name="reload")
@click.argument('feed', type=str, required=False)
def network_reload_feed(feed=False):
    """
    Reload network feed(s) from source
    """
    import menoa.utils.network_utils as network_utils
    
    if feed:
        console.print(f"[yellow]Reloading {feed}...[/yellow]")
        network_utils.update_feed(feed)
        console.print("[green]Feed reloaded[/green]")
    else:
        console.print("[yellow]Reloading feeds...[/yellow]")
        network_utils.update_all_feeds()
        console.print("[green]Feeds reloaded[/green]")   

    console.print("[green]Network feed reloaded.[/green]")

@network.command(name="add")
@click.option('--index', type=str, required=True)
@click.option('--name', type=str, required=True)
@click.option('--description', type=str, required=True)
@click.option('--format', 'feed_format', type=click.Choice(["plain", "csv", "misp", "command"]), required=True)
@click.option('--url', type=str, help="Feed url or local path (plain, csv, misp)")
@click.option('--column', type=str, help="Header name or 0-based column number holding the IP/URL (csv)")
@click.option('--command', type=str, help="Command that prints one indicator per line (command)")
@click.option('--api-key-env', type=str, help="Environment variable holding the API key (misp)")
def network_add_feed(index, name, description, feed_format, url, column, command, api_key_env):
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
def network_remove_feed(index):
    """
    Remove an existing network feed
    """
    import menoa.utils.network_utils as network_utils
    
    console.print(f"[yellow]Removing network feed: {index}...[/yellow]")
    network_utils.remove_feed(index)
    console.print("[green]Network feed removed.[/green]")

@network.command(name="feeds")
def network_list_feeds():
    """
    Show current network feeds.
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
@click.argument('seconds', type=int, required=False)
def network_set_delay(update, seconds=False):
    """
    Set/get network scan or feed update delay (in seconds). If no delay is passed, prints the delay and exits
    """
    import menoa.utils.network_utils as network_utils
    
    if not seconds and update:
        console.print(f"[green]Feed update delay: {network_utils.get_delay()['feed_update_delay']}[/green]")
    elif not seconds and not update:
        console.print(f"[green]Scan delay: {network_utils.get_delay()['scan_delay']}[/green]")
    elif seconds and update:
        network_utils.set_feed_update_delay(seconds)
        console.print(f"[green]Set feed update delay to {seconds}")
    else:
        network_utils.set_scanning_delay(seconds)
        console.print(f"[green]Set scanning delay to {seconds}")

@network.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def network_toggle_background_on(on, off):
    """    
    Toggle network background scanning on
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
def process():
    """Process scanning related commands"""
    pass

@process.command(name="scan")
@click.option('--threshold', type=float, required=False, help="Defaults to the threshold in the config")
@click.option('--quiet', '-q', is_flag=True, help="Don't warn about using your own unsigned model")
def process_scan(threshold=None, quiet=False):
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

    #print(results)
    
    if not "Malicious" in results[1]:
        console.print("[green]No malicious processes found[/green]")

    else:
        console.print("[red]Malicious processes found![/red]")
        table = Table(title="Process Scan Results", box=box.ROUNDED)

        table.add_column("PID", justify="right", style="cyan", no_wrap=True)
        table.add_column("Prediction", style="magenta")
        table.add_column("Confidence", style="magenta")

        for pid, pred, conf in zip(results[0], results[1], results[2]):
            #print(conf, threshold, conf>threshold)
            if pred == "Malicious" and conf >= threshold:
                table.add_row(str(pid), pred, f"{conf:.4f}")

        console.print(table)

@process.command(name="delay")
@click.argument('seconds', type=float, required=False)
def process_set_delay(seconds=False):
    """
    Set/get process scan delay (in seconds). If no delay is passed, prints the delay and exits
    """

    import menoa.utils.process_utils as process_utils

    if not seconds:
        console.print(f"[green]Delay: {process_utils.get_scanning_delay()}[/green]")
    else:
        process_utils.set_scanning_delay(seconds)
        console.print(f"[green]Process scan delay set to {seconds} seconds[/green]")

@process.command(name="threshold")
@click.argument('threshold', type=float, required=False)
def process_get_threshold(threshold=False):
    """
    Set/get process scan detection threshold. If no threshold is passed, prints the delay and exits
    """

    import menoa.utils.process_utils as process_utils

    if not threshold:
        console.print(f"[green]Threshold: {process_utils.get_process_threshold()}[/green]")
    else:
        process_utils.set_scanning_threshold(threshold)
        console.print(f"[green]Process scan threshold set to {threshold}[/green]")

@process.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def process_toggle_background_on(on, off):
    """    
    Toggle network background scanning on
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
def process_model(source, public_key, use_default):
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
def process_keygen(private_key):
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
def process_sign(model, private_key, model_version):
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
def attestation():
    """Attestation related commands"""
    pass

@attestation.command(name="delay")
@click.argument('seconds', type=float, required=False)
def attestation_set_delay(seconds=False):
    """
    Set/get process scan delay (in seconds). If no delay is passed, prints the delay and exits
    """

    if not seconds:
        console.print(f"[green]Delay: {attestation_utils.get_scanning_delay()}[/green]")
    else:
        attestation_utils.set_scanning_delay(seconds)
        console.print(f"[green]Process scan delay set to {seconds} seconds[/green]")

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
def attestation_toggle_background_on(on, off):
    """    
    Toggle network background scanning on
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
def shell():
    """Bash intepreter related commands"""
    pass

@shell.command(name="explain")
@click.argument('source', type=str)
def shell_interpret_source(source):
    """
    Interpret and execute a single bash line or file
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
def init():
    """If stuff in .menoa doesn't exist, create it"""
    failures = initialize()
    if failures:
        console.print("[red]Some setup steps failed, run `menoa init` to retry:[/red]\n" + "\n".join(failures))
        sys.exit(1)
    console.print("[green]Menoa is set up[/green]")

@cli.command()
def fix():
    """Write defaults to .menoa"""
    rewrite()

def main():
    cli()

if __name__ == "__main__":
    main()