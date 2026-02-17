"""Main GTK4 application for FileSnitch."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib

from filesnitch_ui.dbus_client import get_client


class FilesnitchApp(Adw.Application):
    """Main FileSnitch GTK4 application."""

    def __init__(self):
        super().__init__(
            application_id="org.filesnitch.UI",
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        self.client = None
        self.main_window = None

    def do_activate(self):
        self.client = get_client()

        # Subscribe to permission request signals
        self.client.on_permission_request(self._on_permission_request)

        # Show main window if no windows exist
        if not self.get_active_window():
            from filesnitch_ui.main_window import MainWindow
            self.main_window = MainWindow(application=self)
            self.main_window.present()

    def _on_permission_request(self, request_id, pid, executable, target_path, access_type, app_name, timestamp):
        """Handle incoming permission request signal."""
        GLib.idle_add(
            self._show_prompt,
            request_id, pid, executable, target_path, access_type, app_name, timestamp,
        )

    def _show_prompt(self, request_id, pid, executable, target_path, access_type, app_name, timestamp):
        """Show the permission prompt popup on the main thread."""
        from filesnitch_ui.prompt_window import PromptWindow
        prompt = PromptWindow(
            application=self,
            client=self.client,
            request_id=request_id,
            pid=pid,
            executable=executable,
            target_path=target_path,
            access_type=access_type,
            app_name=app_name,
        )
        prompt.present()
        return GLib.SOURCE_REMOVE
