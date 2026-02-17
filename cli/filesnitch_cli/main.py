"""FileSnitch CLI - command line interface for filesnitchd."""

import json
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()


def get_client():
    """Get a D-Bus client, with error handling."""
    try:
        from filesnitch_dbus.client import FilesnitchClient
        return FilesnitchClient()
    except Exception as e:
        console.print(f"[red]Error connecting to filesnitchd:[/red] {e}")
        console.print("Is the daemon running? Try: systemctl start filesnitchd")
        sys.exit(1)


@click.group()
def cli():
    """FileSnitch - interactive file access firewall for your home directory."""
    pass


@cli.command()
def status():
    """Show daemon status."""
    client = get_client()
    s = client.get_status()
    config = client.get_config()

    table = Table(title="FileSnitch Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Operation Mode", str(s.get("operation_mode", "unknown")))
    table.add_row("Protection Mode", str(s.get("protection_mode", "unknown")))
    table.add_row("Pending Requests", str(s.get("pending_requests", 0)))
    table.add_row("Default Action", str(config.get("default_action", "unknown")))
    table.add_row("Prompt Timeout", f"{config.get('prompt_timeout', 30)}s")

    console.print(table)


@cli.group()
def rules():
    """Manage access rules."""
    pass


@rules.command("list")
@click.option("--app", default=None, help="Filter by application path")
@click.option("--path", default=None, help="Filter by target path")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def rules_list(app, path, json_output):
    """List all rules."""
    client = get_client()
    filter_dict = {}
    if app:
        filter_dict["app"] = app
    if path:
        filter_dict["path"] = path
    rule_list = client.list_rules(filter_dict if filter_dict else None)

    if json_output:
        click.echo(json.dumps(rule_list, indent=2, default=str))
        return

    table = Table(title="FileSnitch Rules")
    table.add_column("ID", style="dim")
    table.add_column("Application", style="cyan")
    table.add_column("Path", style="yellow")
    table.add_column("Permission")
    table.add_column("Action")
    table.add_column("Expires")
    table.add_column("Hits", justify="right")

    for rule in rule_list:
        action_style = "green" if rule.get("action") == "allow" else "red"
        table.add_row(
            str(rule.get("id", "")),
            str(rule.get("executable", "")),
            str(rule.get("path_pattern", "")),
            str(rule.get("permission", "")),
            f"[{action_style}]{rule.get('action', '')}[/{action_style}]",
            str(rule.get("expires_at", "never") or "never"),
            str(rule.get("hit_count", 0)),
        )

    console.print(table)


@rules.command("add")
@click.option("--app", required=True, help="Executable path")
@click.option("--path", required=True, help="Target path pattern")
@click.option("--permission", type=click.Choice(["read", "write", "read_write"]), default="read_write")
@click.option("--action", type=click.Choice(["allow", "deny"]), required=True)
def rules_add(app, path, permission, action):
    """Add a new rule."""
    client = get_client()
    rule_id = client.add_rule({
        "executable": app,
        "path_pattern": path,
        "permission": permission,
        "action": action,
    })
    console.print(f"[green]Rule {rule_id} created.[/green]")


@rules.command("remove")
@click.argument("rule_id", type=int)
def rules_remove(rule_id):
    """Remove a rule by ID."""
    client = get_client()
    client.delete_rule(rule_id)
    console.print(f"[green]Rule {rule_id} deleted.[/green]")


@rules.command("export")
def rules_export():
    """Export rules as JSON."""
    client = get_client()
    click.echo(client.export_rules())


@rules.command("import")
@click.argument("file", type=click.File("r"), default="-")
def rules_import(file):
    """Import rules from JSON file (or stdin)."""
    client = get_client()
    data = file.read()
    count = client.import_rules(data)
    console.print(f"[green]Imported {count} rules.[/green]")


@cli.command()
@click.option("--follow", "-f", is_flag=True, help="Follow new events")
@click.option("--app", default=None, help="Filter by application")
@click.option("--path", default=None, help="Filter by path")
@click.option("--limit", "-n", default=50, help="Number of events to show")
def log(follow, app, path, limit):
    """Show the event log."""
    client = get_client()

    if not follow:
        filter_dict = {}
        if app:
            filter_dict["app"] = app
        if path:
            filter_dict["path"] = path
        events = client.get_recent_events(limit, filter_dict if filter_dict else None)
        table = Table(title="Recent Events")
        table.add_column("Time", style="dim")
        table.add_column("Application", style="cyan")
        table.add_column("Path", style="yellow")
        table.add_column("Access")
        table.add_column("Decision")
        table.add_column("Reason")

        for event in events:
            decision_style = "green" if event.get("decision") == "allow" else "red"
            table.add_row(
                str(event.get("timestamp", "")),
                str(event.get("executable", "")),
                str(event.get("target_path", "")),
                str(event.get("access_type", "")),
                f"[{decision_style}]{event.get('decision', '')}[/{decision_style}]",
                str(event.get("reason", "")),
            )

        console.print(table)
    else:
        from dasbus.loop import EventLoop
        loop = EventLoop()

        def on_event(event):
            decision_style = "green" if event.get("decision") == "allow" else "red"
            console.print(
                f"[dim]{event.get('timestamp', '')}[/dim] "
                f"[cyan]{event.get('executable', '')}[/cyan] "
                f"[yellow]{event.get('target_path', '')}[/yellow] "
                f"{event.get('access_type', '')} "
                f"[{decision_style}]{event.get('decision', '')}[/{decision_style}]"
            )

        client.on_event_logged(on_event)
        console.print("[dim]Following event log (Ctrl+C to stop)...[/dim]")
        try:
            loop.run()
        except KeyboardInterrupt:
            pass


@cli.command()
def watch():
    """Interactive mode - approve/deny file access requests in real time."""
    client = get_client()
    from filesnitch_cli.watch import WatchMode
    watcher = WatchMode(client)
    watcher.run()


@cli.group()
def config():
    """View and change configuration."""
    pass


@config.command("get")
@click.argument("key", required=False)
def config_get(key):
    """Get configuration value(s)."""
    client = get_client()
    cfg = client.get_config()
    if key:
        if key in cfg:
            console.print(f"{key} = {cfg[key]}")
        else:
            console.print(f"[red]Unknown config key: {key}[/red]")
    else:
        for k, v in cfg.items():
            console.print(f"{k} = {v}")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a configuration value."""
    client = get_client()
    client.set_config(key, value)
    console.print(f"[green]{key} set to {value}[/green]")


def main():
    cli()
