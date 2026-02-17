"""Event log tab."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib, GObject


class EventObject(GObject.Object):
    """GObject wrapper for an event dict."""

    def __init__(self, data):
        super().__init__()
        self.data = data

    @GObject.Property(type=str)
    def timestamp(self):
        return str(self.data.get("timestamp", ""))

    @GObject.Property(type=str)
    def executable(self):
        return str(self.data.get("executable", ""))

    @GObject.Property(type=str)
    def target_path(self):
        return str(self.data.get("target_path", ""))

    @GObject.Property(type=str)
    def access_type(self):
        return str(self.data.get("access_type", ""))

    @GObject.Property(type=str)
    def decision(self):
        return str(self.data.get("decision", ""))

    @GObject.Property(type=str)
    def reason(self):
        return str(self.data.get("reason", ""))


class LogPage(Gtk.Box):
    """Event log tab with live-updating list."""

    def __init__(self, parent_window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.parent_window = parent_window
        self.set_margin_top(8)
        self.set_margin_bottom(8)
        self.set_margin_start(8)
        self.set_margin_end(8)

        # Toolbar
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Filter events...")
        self.search_entry.set_hexpand(True)
        toolbar.append(self.search_entry)

        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh")
        refresh_btn.connect("clicked", self._on_refresh)
        toolbar.append(refresh_btn)

        self.append(toolbar)

        # List store
        self.store = Gio.ListStore(item_type=EventObject)

        # Column view
        selection = Gtk.NoSelection(model=self.store)
        self.column_view = Gtk.ColumnView(model=selection)
        self.column_view.set_vexpand(True)

        for prop, title, width in [
            ("timestamp", "Time", 160),
            ("executable", "Application", 180),
            ("target_path", "Path", 200),
            ("access_type", "Access", 60),
            ("decision", "Decision", 60),
            ("reason", "Reason", 80),
        ]:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._on_factory_setup)
            factory.connect("bind", self._on_factory_bind, prop)
            column = Gtk.ColumnViewColumn(title=title, factory=factory)
            column.set_fixed_width(width)
            self.column_view.append_column(column)

        scroll = Gtk.ScrolledWindow()
        scroll.set_child(self.column_view)
        scroll.set_vexpand(True)
        self.append(scroll)

        # Load events and subscribe to live updates
        GLib.idle_add(self._load_events)
        GLib.idle_add(self._subscribe_signals)

    def _on_factory_setup(self, factory, list_item):
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        list_item.set_child(label)

    def _on_factory_bind(self, factory, list_item, prop_name):
        item = list_item.get_item()
        label = list_item.get_child()
        if item:
            label.set_label(item.get_property(prop_name))

    def _load_events(self):
        try:
            client = self.parent_window.get_application().client
            events = client.get_recent_events(100)
            self.store.remove_all()
            for event in events:
                self.store.append(EventObject(event))
        except Exception as e:
            print(f"Failed to load events: {e}")
        return GLib.SOURCE_REMOVE

    def _subscribe_signals(self):
        try:
            client = self.parent_window.get_application().client
            client.on_event_logged(self._on_event_logged)
        except Exception:
            pass
        return GLib.SOURCE_REMOVE

    def _on_event_logged(self, event):
        GLib.idle_add(self._add_event, event)

    def _add_event(self, event):
        self.store.insert(0, EventObject(event))
        return GLib.SOURCE_REMOVE

    def _on_refresh(self, button):
        self._load_events()
