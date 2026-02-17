"""Rules management tab."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib, GObject


class RuleObject(GObject.Object):
    """GObject wrapper for a rule dict."""

    def __init__(self, data):
        super().__init__()
        self.data = data

    @GObject.Property(type=str)
    def rule_id(self):
        return str(self.data.get("id", ""))

    @GObject.Property(type=str)
    def executable(self):
        return str(self.data.get("executable", ""))

    @GObject.Property(type=str)
    def path_pattern(self):
        return str(self.data.get("path_pattern", ""))

    @GObject.Property(type=str)
    def permission(self):
        return str(self.data.get("permission", ""))

    @GObject.Property(type=str)
    def action(self):
        return str(self.data.get("action", ""))

    @GObject.Property(type=str)
    def expires_at(self):
        val = self.data.get("expires_at", "")
        return str(val) if val else "never"

    @GObject.Property(type=str)
    def hit_count(self):
        return str(self.data.get("hit_count", 0))

    @GObject.Property(type=bool, default=True)
    def enabled(self):
        return bool(self.data.get("enabled", True))


class RulesPage(Gtk.Box):
    """Rules tab with sortable table and CRUD controls."""

    def __init__(self, parent_window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.parent_window = parent_window
        self.set_margin_top(8)
        self.set_margin_bottom(8)
        self.set_margin_start(8)
        self.set_margin_end(8)

        # Toolbar with search + buttons
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search rules...")
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", self._on_search_changed)
        toolbar.append(self.search_entry)

        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh")
        refresh_btn.connect("clicked", self._on_refresh)
        toolbar.append(refresh_btn)

        delete_btn = Gtk.Button(icon_name="user-trash-symbolic")
        delete_btn.set_tooltip_text("Delete selected rule")
        delete_btn.connect("clicked", self._on_delete)
        toolbar.append(delete_btn)

        self.append(toolbar)

        # List store and model
        self.store = Gio.ListStore(item_type=RuleObject)

        # Column view
        self.selection = Gtk.SingleSelection(model=self.store)
        self.column_view = Gtk.ColumnView(model=self.selection)
        self.column_view.set_vexpand(True)

        # Add columns
        for prop, title, width in [
            ("rule_id", "ID", 50),
            ("executable", "Application", 200),
            ("path_pattern", "Path", 200),
            ("permission", "Permission", 80),
            ("action", "Action", 60),
            ("expires_at", "Expires", 100),
            ("hit_count", "Hits", 50),
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

        # Load rules on first show
        GLib.idle_add(self._load_rules)

    def _on_factory_setup(self, factory, list_item):
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        list_item.set_child(label)

    def _on_factory_bind(self, factory, list_item, prop_name):
        item = list_item.get_item()
        label = list_item.get_child()
        if item:
            label.set_label(item.get_property(prop_name))

    def _load_rules(self):
        try:
            client = self.parent_window.get_application().client
            rules = client.list_rules()
            self.store.remove_all()
            for rule in rules:
                self.store.append(RuleObject(rule))
        except Exception as e:
            print(f"Failed to load rules: {e}")
        return GLib.SOURCE_REMOVE

    def _on_refresh(self, button):
        self._load_rules()

    def _on_search_changed(self, entry):
        # Simple client-side filter - reload with filter
        self._load_rules()

    def _on_delete(self, button):
        selected = self.selection.get_selected_item()
        if selected:
            try:
                client = self.parent_window.get_application().client
                client.delete_rule(int(selected.data.get("id", 0)))
                self._load_rules()
            except Exception as e:
                print(f"Failed to delete rule: {e}")
