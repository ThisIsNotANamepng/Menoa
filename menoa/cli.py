"""
CLI interface for Menoa

Clam
- Basic/Full/Custom Scan
- Reload feed from source
- Add/remove feed
- See current feeds (main.cld, daily.cvd, any custom feeds)
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
import click
from rich.console import Console
from pathlib import Path
from tqdm import tqdm
from rich.table import Table
from rich import box

import utils.attestation_utils as attestation_utils
#import utils.clam_utils as clam_utils
#import utils.network_utils as network_utils
#import utils.process_utils as process_utils
import utils.script_utils as script_utils

console = Console()

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.1.0", prog_name="cli_tool")
def cli():
    """
    The CLI frontend for Menoa. See menoa.org/docs more information 
    """
    pass

@cli.group()
def clam():
    """ClamAV antivirus related commands"""
    pass

def scan(path):
    console.print("[yellow]Counting total files...  [/yellow]", end='')
    total_files = clam_utils.get_scan_total(path)
    print(total_files)

    #print(total_files)
    console.print("[yellow]Loading signatures from (get used feeds here)...[/yellow]", end='')
    progress = None

    first = True

    infected = []
    sigs = []

    for file, result in clam_utils.scan_path_streaming(path):
        
        #print(f"{file} {result}")
        if result != "OK" and file[0] == "/":
            infected.append(file)
            sigs.append(result)

        if progress is None: # If the progress bar is created before the loop it's hung at 0% while the signatures are loaded into memory
            print()
            progress = tqdm(desc="Scanning files", unit="file", total=total_files)
        
        progress.update(1)

    if progress:
        progress.close()
        progress.close()

    if len(infected) == 0:
        console.print("[green]No malware found![/green]")
    else:
        console.print("[red]Malware found[/red]")

        for path, sig in zip(infected, sigs):
            print(path, sig)

@clam.command(name="quick")
def clam_quick_scan():
    """
    Scans places in which malware is most often found (~/Downloads)
    """
    import utils.clam_utils as clam_utils

    console.print("[blue]Starting quick scan[/blue]")
    scan(str(Path.home()) + "/Downloads/")

@clam.command(name="full")
def clam_full_scan():
    """
    Scans the whole system from /
    """
    import utils.clam_utils as clam_utils

    console.print("[blue]Starting full system scan from /[/blue]")
    scan("/")


@clam.command(name="scan")
@click.argument('path', type=str)
def clam_custom_scan(path):
    """
    Perform a custom Clam scan using a given file/dir path
    """
    import utils.clam_utils as clam_utils

    console.print(f"[blue]Starting scan from: {path}[/blue]")
    scan(path)

@clam.command(name="reload")
@click.argument('feed', type=str, required=False)
def clam_reload_feed(feed=False):
    """
    Reload Clam feed from source. If a name or a url is passed then just reload that feed, else reload all
    """
    import utils.clam_utils as clam_utils

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
@click.option('--supports-versioning', is_flag=True, default=False)
@click.option('--centralize', is_flag=True, default=False)
def clam_add_feed(index, name, url, description, local_path, supports_versioning, centralize):
    """
    Add a new Clam feed.
    """
    import utils.clam_utils as clam_utils

    clam_utils.add_feed(index, name, url, description, local_path, supports_versioning, centralize)
    console.print(f"[green]Added {name}![/green]")

@clam.command(name="remove")
@click.option('--index', type=str, required=True)
def clam_remove_feed(index):
    """
    Remove an existing Clam feed
    """
    import utils.clam_utils as clam_utils

    clam_utils.remove_feed(index)
    console.print(f"[green]{index} removed![/green]")

@clam.command(name="feeds")
def clam_list_feeds():
    """
    Print a table of the current Clam feeds
    """
    import utils.clam_utils as clam_utils

    table = Table(title="ClamAV Signature Feeds", box=box.ROUNDED)

    table.add_column("Index", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("Description", style="magenta")
    table.add_column("Upstream URL", style="magenta")
    table.add_column("Local Storage", style="magenta")
    table.add_column("Last Refreshed", style="magenta")
    table.add_column("Upstream Supports Versioning", style="magenta")

    feeds = clam_utils.list_feeds()

    for i in feeds:
        table.add_row(i, feeds[i]["name"], feeds[i]["description"], feeds[i]["url"], feeds[i]["local_path"], str(feeds[i]["last_refreshed"]), str(feeds[i]["supports_versioning"]))

    console.print(table)

@clam.command(name="delay")
@click.option('--scan', required=False, is_flag=True)
@click.option('--refresh', required=False, is_flag=True)
@click.argument('seconds', type=int, required=False)
def clam_set_delay(scan, refresh, seconds=False):
    """
    Set/get scan delay (in seconds) for Clam. If no delay is passed, prints the delay and exits
    """
    import utils.clam_utils as clam_utils

    if not seconds and refresh:
        console.print(f"[green]Feed refresh delay: {clam_utils.get_delay()["feed_update_delay"]}[/green]")
    elif not seconds and not refresh:
        console.print(f"[green]Scan delay: {clam_utils.get_delay()["scan_delay"]}[/green]")
    elif seconds and refresh:
        clam_utils.set_feed_refresh_delay(seconds)
        console.print(f"[green]Set feed refresh delay to {seconds}")
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
    import utils.clam_utils as clam_utils

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
    Perform a network scan
    """
    import utils.network_utils as network_utils

    console.print("[yellow]Starting network scan...[/yellow]")
    # Implementation
    console.print("[green]Network scan completed.[/green]")

@network.command(name="reload")
def network_reload_feed():
    """
    Reload network feed(s) from source
    """
    import utils.network_utils as network_utils
    
    console.print("[yellow]Reloading network feed...[/yellow]")
    # Implementation
    console.print("[green]Network feed reloaded.[/green]")

@network.command(name="add")
@click.argument('url', type=str)
def network_add_feed(url):
    """
    Add a new network feed from a local file or remote url
    """
    import utils.network_utils as network_utils
    
    console.print(f"[yellow]Adding network feed: {url}...[/yellow]")
    # Implementation
    console.print("[green]Network feed added.[/green]")

@network.command(name="remove")
@click.argument('url', type=str)
def network_remove_feed(url):
    """
    Remove an existing network feed
    """
    import utils.network_utils as network_utils
    
    console.print(f"[yellow]Removing network feed: {url}...[/yellow]")
    # Implementation
    console.print("[green]Network feed removed.[/green]")

@network.command(name="feeds")
def network_list_feeds():
    """
    Show current network feeds.
    """
    import utils.network_utils as network_utils
    
    console.print("[yellow]Fetching network feeds...[/yellow]")
    # Implementation
    console.print("[green]Showing feeds[/green]")

@network.command(name="delay")
@click.argument('seconds', type=int)
def network_set_delay(seconds=False):
    """
    Set/get network scan delay (in seconds). If no delay is passed, prints the delay and exits
    """
    import utils.network_utils as network_utils
    
    if not seconds:
        console.print("[green]Delay: [/green]")
    else:
        # Implementation
        console.print(f"[green]Network scan delay set to {seconds} seconds...[/green]")

@network.command(name="on")
def network_toggle_background_on():
    """
    import utils.network_utils as network_utils
    
    Toggle network background scanning on
    """
    console.print("[yellow]Toggling network background scan on...[/yellow]")
    # Implementation
    console.print("[green]Background scan toggled on[/green]")

@network.command(name="off")
def network_toggle_background_off():
    """
    Toggle network background scanning off
    """
    import utils.network_utils as network_utils
    
    console.print("[yellow]Toggling network background scan off...[/yellow]")
    # Implementation
    console.print("[green]Background scan toggled off[/green]")

@network.command(name="toggle")
def network_toggle_background():
    """
    Toggle network background scanning
    """
    import utils.network_utils as network_utils
    
    console.print("[yellow]Toggling network background scan...[/yellow]")
    # Implementation
    console.print("[green]Background scan toggled[/green]")


@cli.group()
def process():
    """Process scanning related commands"""
    import utils.process_utils as process_utils
    pass

@process.command(name="scan")
def process_scan():
    """
    Perform a process scan.
    """
    console.print("[yellow]Starting process scan...[/yellow]")
    # Implementation
    console.print("[green]Process scan completed.[/green]")

@process.command(name="delay")
@click.argument('seconds', type=float)
def process_set_threshold(seconds=False):
    """
    Set/get process scan delay (in seconds). If no delay is passed, prints the delay and exits
    """
    if not seconds:
        console.print("[green]Delay: [/green]")
    else:
        # Implementation
        console.print(f"[green]Process scan delay set to {seconds} seconds...[/green]")

@process.command(name="threshold")
@click.argument('threshold', type=float)
def process_get_threshold(threshold=False):
    """
    Set/get process scan detection threshold. If no threshold is passed, prints the delay and exits
    """
    if not threshold:
        console.print("[green]Threshold: [/green]")
    else:
        # Implementation
        console.print(f"[green]Process scan threshold set to {threshold}[/green]")

@process.command(name="add")
@click.argument('url', type=str)
def process_add_feed(url):
    """
    Add a new process model
    """
    console.print(f"[yellow]Adding process classification model: {url}...[/yellow]")
    # Implementation
    console.print("[green]Process model added[/green]")

@process.command(name="remove")
@click.argument('url', type=str)
def process_remove_feed(url):
    """
    Remove an existing process model
    """
    console.print(f"[yellow]Removing process model: {url}...[/yellow]")
    # Implementation
    console.print("[green]Process feed removed.[/green]")

@process.command(name="list")
def process_list_feeds():
    """
    Show current process models
    """
    console.print("[yellow]Fetching process models...[/yellow]")
    # Implementation
    console.print("[green]Listed process models...[/green]")

@process.command(name="off")
def process_toggle_background_off():
    """
    Toggle process background monitoring off
    """
    console.print("[yellow]Toggling process background monitoring off...[/yellow]")
    # Implementation
    console.print("[green]Background monitoring off[/green]")

@process.command(name="on")
def process_toggle_background_on():
    """
    Toggle process background monitoring on
    """
    console.print("[yellow]Toggling process background monitoring on...[/yellow]")
    # Implementation
    console.print("[green]Background monitoring on[/green]")

@process.command(name="toggle")
def process_toggle_background():
    """
    Toggle process background monitoring on/off
    """
    console.print("[yellow]Toggling process background monitoring...[/yellow]")
    # Implementation
    console.print("[green]Background monitoring toggled[/green]")

# --------------------
# On-device Personalized Learning Commands
# --------------------
@cli.group(name="ondevice")
def ondevice():
    """On-device personalized learning commands"""
    pass

@ondevice.command(name="toggle")
def ondevice_toggle():
    """
    Toggle on-device personalized learning on/off.
    """
    console.print("[yellow]Toggling on-device personalized learning...[/yellow]")
    # Implementation
    console.print("[green]On-device learning toggled.[/green]")




@cli.group()
def attestation():
    """Attestation related commands"""
    pass

@attestation.command(name="delay")
def attest_get_delay(seconds=False):
    """
    Set/get scan delay (in seconds) for attestation. If no delay is passed, prints the delay and exits
    """
    if not seconds:
        console.print("[green]Delay: [/green]")
    else:
        # Implementation
        console.print(f"[green]Attestation delay set to {seconds} seconds...[/green]")

@attestation.command(name="status")
def attest_get_status():
    """
    Get current attestation status
    """
    console.print("[yellow]Fetching attestation status...[/yellow]")
    # Implementation
    console.print(f"Current status: [bold]{status}[/bold]")

@attestation.command(name="toggle")
@click.option('--on', required=False, is_flag=True)
@click.option('--off', required=False, is_flag=True)
def attest_toggle_background(on, off):
    """
    Toggle attestation background scanning on/off
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
def commands():
    """Bash command interpreter"""
    pass

@commands.command(name="explain")
@click.argument('source', type=str)
def shell_interpret_source(source):
    """
    Interpret and execute a single bash line or file
    """
    console.print(f"[yellow]Interpreting: {source}...[/yellow]")
    # Implementation
    console.print("[green]Explained[/green]")


if __name__ == "__main__":
    cli()