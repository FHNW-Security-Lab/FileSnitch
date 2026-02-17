"""Settings tab."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib


class SettingsPage(Adw.PreferencesPage):
    """Settings tab using libadwaita preferences widgets."""

    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window

        # --- Mode group ---
        mode_group = Adw.PreferencesGroup(title="Mode")

        # Operation mode
        self.operation_row = Adw.SwitchRow(
            title="Enforce Mode",
            subtitle="When off, runs in learning mode (all accesses allowed and logged)",
        )
        self.operation_row.connect("notify::active", self._on_operation_changed)
        mode_group.add(self.operation_row)

        # Protection mode
        self.protection_row = Adw.SwitchRow(
            title="Protect Everything",
            subtitle="When off, only critical files are protected",
        )
        self.protection_row.connect("notify::active", self._on_protection_changed)
        mode_group.add(self.protection_row)

        # Default action
        self.default_action_row = Adw.ComboRow(
            title="Default Action",
            subtitle="Action when prompt times out",
        )
        self.default_action_row.set_model(Gtk.StringList.new(["deny", "allow"]))
        self.default_action_row.connect("notify::selected", self._on_default_action_changed)
        mode_group.add(self.default_action_row)

        # Prompt timeout
        adjustment = Gtk.Adjustment(value=30, lower=10, upper=120, step_increment=5)
        self.timeout_row = Adw.SpinRow(
            title="Prompt Timeout (seconds)",
            adjustment=adjustment,
        )
        self.timeout_row.connect("notify::value", self._on_timeout_changed)
        mode_group.add(self.timeout_row)

        self.add(mode_group)

        # --- Critical files group ---
        critical_group = Adw.PreferencesGroup(
            title="Critical Files",
            description="Paths relative to home directory that receive extra protection",
        )

        self.critical_listbox = Gtk.ListBox()
        self.critical_listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        self.critical_listbox.add_css_class("boxed-list")
        critical_group.add(self.critical_listbox)

        # Add/remove buttons
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.critical_entry = Gtk.Entry()
        self.critical_entry.set_placeholder_text(".config/sensitive-app")
        self.critical_entry.set_hexpand(True)
        btn_box.append(self.critical_entry)

        add_btn = Gtk.Button(icon_name="list-add-symbolic")
        add_btn.connect("clicked", self._on_add_critical)
        btn_box.append(add_btn)

        critical_group.add(btn_box)
        self.add(critical_group)

        # Load current config
        GLib.idle_add(self._load_config)

    def _load_config(self):
        try:
            client = self.parent_window.get_application().client
            config = client.get_config()

            # Block signals during load
            self.operation_row.set_active(
                str(config.get("operation_mode", "learning")) == "enforce"
            )
            self.protection_row.set_active(
                str(config.get("protection_mode", "critical_only")) == "everything"
            )

            default_action = str(config.get("default_action", "deny"))
            self.default_action_row.set_selected(0 if default_action == "deny" else 1)

            timeout = config.get("prompt_timeout", 30)
            self.timeout_row.set_value(float(timeout))

            # Load critical paths
            paths = client.get_critical_paths()
            self._populate_critical_paths(paths)
        except Exception as e:
            print(f"Failed to load config: {e}")
        return GLib.SOURCE_REMOVE

    def _populate_critical_paths(self, paths):
        # Clear existing
        while True:
            row = self.critical_listbox.get_row_at_index(0)
            if row is None:
                break
            self.critical_listbox.remove(row)

        for path in paths:
            row = Adw.ActionRow(title=path)
            remove_btn = Gtk.Button(icon_name="list-remove-symbolic")
            remove_btn.set_valign(Gtk.Align.CENTER)
            remove_btn.connect("clicked", self._on_remove_critical, path)
            row.add_suffix(remove_btn)
            self.critical_listbox.append(row)

    def _on_operation_changed(self, row, _pspec):
        try:
            client = self.parent_window.get_application().client
            mode = "enforce" if row.get_active() else "learning"
            client.set_config("operation_mode", mode)
        except Exception as e:
            print(f"Failed to set operation mode: {e}")

    def _on_protection_changed(self, row, _pspec):
        try:
            client = self.parent_window.get_application().client
            mode = "everything" if row.get_active() else "critical_only"
            client.set_config("protection_mode", mode)
        except Exception as e:
            print(f"Failed to set protection mode: {e}")

    def _on_default_action_changed(self, row, _pspec):
        try:
            client = self.parent_window.get_application().client
            actions = ["deny", "allow"]
            client.set_config("default_action", actions[row.get_selected()])
        except Exception as e:
            print(f"Failed to set default action: {e}")

    def _on_timeout_changed(self, row, _pspec):
        try:
            client = self.parent_window.get_application().client
            client.set_config("prompt_timeout", str(int(row.get_value())))
        except Exception as e:
            print(f"Failed to set timeout: {e}")

    def _on_add_critical(self, button):
        path = self.critical_entry.get_text().strip()
        if not path:
            return
        try:
            client = self.parent_window.get_application().client
            client.add_critical_path(path)
            self.critical_entry.set_text("")
            # Reload
            paths = client.get_critical_paths()
            self._populate_critical_paths(paths)
        except Exception as e:
            print(f"Failed to add critical path: {e}")

    def _on_remove_critical(self, button, path):
        try:
            client = self.parent_window.get_application().client
            client.remove_critical_path(path)
            paths = client.get_critical_paths()
            self._populate_critical_paths(paths)
        except Exception as e:
            print(f"Failed to remove critical path: {e}")
