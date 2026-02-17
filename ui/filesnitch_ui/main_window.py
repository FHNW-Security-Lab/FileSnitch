"""Main application window with tabs."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw

from filesnitch_ui.rules_page import RulesPage
from filesnitch_ui.log_page import LogPage
from filesnitch_ui.settings_page import SettingsPage


class MainWindow(Adw.ApplicationWindow):
    """Main FileSnitch window with Rules, Event Log, and Settings tabs."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_default_size(900, 600)
        self.set_title("FileSnitch")

        # Header bar
        header = Adw.HeaderBar()

        # Notebook with 3 tabs
        notebook = Gtk.Notebook()
        notebook.set_vexpand(True)
        notebook.append_page(RulesPage(self), Gtk.Label(label="Rules"))
        notebook.append_page(LogPage(self), Gtk.Label(label="Event Log"))
        notebook.append_page(SettingsPage(self), Gtk.Label(label="Settings"))

        # Layout
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.append(header)
        box.append(notebook)
        self.set_content(box)
