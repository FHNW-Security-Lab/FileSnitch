"""Interactive watch mode for FileSnitch CLI."""

import sys
import threading
from collections import OrderedDict

from rich.console import Console
from rich.live import Live
from rich.table import Table


console = Console()


class WatchMode:
    """Interactive mode showing pending permission requests.

    Displays a live-updating table of pending requests and accepts
    shorthand commands to approve/deny them.
    """

    def __init__(self, client):
        self.client = client
        self.pending = OrderedDict()
        self.lock = threading.Lock()

    def on_permission_request(self, request_id, pid, executable, target_path, access_type, app_name, timestamp):
        """Callback for incoming permission requests."""
        with self.lock:
            self.pending[request_id] = {
                "request_id": request_id,
                "pid": pid,
                "executable": executable,
                "target_path": target_path,
                "access_type": access_type,
                "app_name": app_name,
                "timestamp": timestamp,
            }

    def make_table(self):
        """Generate the current pending requests table."""
        table = Table(title="Pending Permission Requests")
        table.add_column("#", style="bold", width=4)
        table.add_column("Application", style="cyan")
        table.add_column("Path", style="yellow")
        table.add_column("Access")
        table.add_column("PID", justify="right")

        with self.lock:
            for idx, (req_id, req) in enumerate(self.pending.items(), 1):
                table.add_row(
                    str(idx),
                    f"{req['app_name']} ({req['executable']})",
                    req["target_path"],
                    req["access_type"].upper(),
                    str(req["pid"]),
                )

        return table

    def handle_input(self, user_input):
        """Parse user input and respond to a request.

        Formats:
          1a     -> allow request #1 once
          1d     -> deny request #1 once
          1af    -> allow request #1 forever
          1df    -> deny request #1 forever
          1 allow once
          1 deny forever
          1 allow forever folder
          1 deny 10m recursive
        """
        parts = user_input.strip().split()
        if not parts:
            return

        # Defaults
        path_scope = "exact"
        permission = "readwrite"

        # Parse shorthand like "1a", "1d", "1af"
        first = parts[0]
        if len(first) >= 2 and first[0].isdigit():
            num_str = ""
            rest = ""
            for i, ch in enumerate(first):
                if ch.isdigit():
                    num_str += ch
                else:
                    rest = first[i:]
                    break

            idx = int(num_str)
            action = "allow" if rest.startswith("a") else "deny"
            duration = "forever" if "f" in rest else "once"

            # Check for additional scope/permission args
            if len(parts) > 1:
                path_scope = parts[1]
            if len(parts) > 2:
                permission = parts[2]
        elif len(parts) >= 2:
            try:
                idx = int(parts[0])
            except ValueError:
                console.print("[red]Invalid input. Use: <#>a|d[f] or <#> allow|deny [duration] [scope][/red]")
                return
            action = parts[1]
            duration = parts[2] if len(parts) > 2 else "once"
            if len(parts) > 3:
                path_scope = parts[3]
            if len(parts) > 4:
                permission = parts[4]
        else:
            console.print("[red]Invalid input. Use: <#>a|d[f] or <#> allow|deny [duration] [scope][/red]")
            return

        with self.lock:
            keys = list(self.pending.keys())
            if idx < 1 or idx > len(keys):
                console.print(f"[red]No request #{idx}[/red]")
                return
            request_id = keys[idx - 1]
            req = self.pending.pop(request_id)

        try:
            self.client.respond_to_request(
                request_id,
                action,
                duration,
                path_scope,
                permission,
            )
            style = "green" if action == "allow" else "red"
            console.print(
                f"[{style}]{action.upper()}[/{style}] "
                f"{req['app_name']} -> {req['target_path']} ({duration})"
            )
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def run(self):
        """Run the interactive watch mode."""
        import gi
        gi.require_version("GLib", "2.0")
        from gi.repository import GLib

        self.client.on_permission_request(self.on_permission_request)

        console.print("[bold]FileSnitch Watch Mode[/bold]")
        console.print("Commands: <#>a (allow once), <#>d (deny once), <#>af (allow forever), <#>df (deny forever)")
        console.print("          <#> allow|deny once|1m|10m|60m|12h|forever [exact|folder|recursive|home]")
        console.print("Press Ctrl+C to exit.\n")

        # Run GLib main loop in background for D-Bus signals
        loop = GLib.MainLoop()
        loop_thread = threading.Thread(target=loop.run, daemon=True)
        loop_thread.start()

        try:
            with Live(self.make_table(), refresh_per_second=2, console=console) as live:
                while True:
                    live.update(self.make_table())
                    try:
                        user_input = console.input("[bold]> [/bold]")
                        self.handle_input(user_input)
                    except EOFError:
                        break
        except KeyboardInterrupt:
            pass
        finally:
            loop.quit()
            console.print("\n[dim]Watch mode ended.[/dim]")
