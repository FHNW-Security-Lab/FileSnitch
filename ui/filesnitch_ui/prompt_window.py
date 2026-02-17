"""Permission request popup window."""

import os
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib


class PromptWindow(Adw.Window):
    """Permission request popup dialog.

    Shows app info, target path, and lets the user choose:
    - Action: Allow / Deny
    - Duration: once, 1m, 10m, 60m, 12h, forever
    - Path scope: exact, folder, recursive, home, custom
    - Permission: read, write, readwrite

    Auto-denies on timeout countdown.
    """

    DURATIONS = [
        ("This time only", "once"),
        ("1 minute", "1m"),
        ("10 minutes", "10m"),
        ("60 minutes", "60m"),
        ("12 hours", "12h"),
        ("Forever", "forever"),
    ]

    def __init__(self, application, client, request_id, pid, executable,
                 target_path, access_type, app_name, timeout=30):
        super().__init__(
            title="FileSnitch - Permission Request",
            default_width=500,
            default_height=480,
            modal=True,
        )

        self.client = client
        self.request_id = request_id
        self.remaining = timeout
        self.responded = False
        self._timer_id = None

        # Keep above other windows
        self.set_deletable(False)

        # Main content
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(20)
        content.set_margin_bottom(20)
        content.set_margin_start(20)
        content.set_margin_end(20)

        # Header with icon and app info
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        icon = self._get_app_icon(executable)
        header.append(icon)

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        name_label = Gtk.Label(label=app_name or os.path.basename(executable))
        name_label.add_css_class("title-2")
        name_label.set_halign(Gtk.Align.START)
        info_box.append(name_label)

        path_label = Gtk.Label(label=executable)
        path_label.add_css_class("dim-label")
        path_label.set_halign(Gtk.Align.START)
        path_label.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        info_box.append(path_label)

        pid_label = Gtk.Label(label=f"PID {pid}")
        pid_label.add_css_class("dim-label")
        pid_label.set_halign(Gtk.Align.START)
        info_box.append(pid_label)

        header.append(info_box)
        content.append(header)

        # Access description
        access_label = Gtk.Label(label=f"wants to {access_type.upper()}:")
        access_label.add_css_class("title-3")
        access_label.set_halign(Gtk.Align.START)
        content.append(access_label)

        target_label = Gtk.Label(label=target_path)
        target_label.set_selectable(True)
        target_label.set_halign(Gtk.Align.START)
        target_label.add_css_class("monospace")
        content.append(target_label)

        content.append(Gtk.Separator())

        # Action: Allow / Deny
        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        action_label = Gtk.Label(label="Action:")
        action_label.set_halign(Gtk.Align.START)
        action_box.append(action_label)

        self.allow_check = Gtk.CheckButton(label="Allow")
        self.deny_check = Gtk.CheckButton(label="Deny")
        self.deny_check.set_group(self.allow_check)
        self.deny_check.set_active(True)
        action_box.append(self.allow_check)
        action_box.append(self.deny_check)
        content.append(action_box)

        # Duration dropdown
        duration_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        duration_label = Gtk.Label(label="Duration:")
        duration_label.set_halign(Gtk.Align.START)
        duration_box.append(duration_label)

        self.duration_dropdown = Gtk.DropDown.new_from_strings(
            [d[0] for d in self.DURATIONS]
        )
        self.duration_dropdown.set_selected(0)
        duration_box.append(self.duration_dropdown)
        content.append(duration_box)

        # Path scope
        scope_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        scope_title = Gtk.Label(label="Apply to:")
        scope_title.set_halign(Gtk.Align.START)
        scope_box.append(scope_title)

        self.scope_exact = Gtk.CheckButton(label=f"This exact file ({os.path.basename(target_path)})")
        scope_box.append(self.scope_exact)

        parent_dir = os.path.dirname(target_path)
        self.scope_folder = Gtk.CheckButton(label=f"This folder ({parent_dir}/*)")
        self.scope_folder.set_group(self.scope_exact)
        self.scope_folder.set_active(True)
        scope_box.append(self.scope_folder)

        self.scope_recursive = Gtk.CheckButton(label=f"Folder + subfolders ({parent_dir}/**)")
        self.scope_recursive.set_group(self.scope_exact)
        scope_box.append(self.scope_recursive)

        self.scope_home = Gtk.CheckButton(label="Entire home directory")
        self.scope_home.set_group(self.scope_exact)
        scope_box.append(self.scope_home)

        custom_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.scope_custom = Gtk.CheckButton(label="Custom:")
        self.scope_custom.set_group(self.scope_exact)
        custom_box.append(self.scope_custom)
        self.scope_custom_entry = Gtk.Entry()
        self.scope_custom_entry.set_hexpand(True)
        self.scope_custom_entry.set_text(parent_dir + "/*")
        custom_box.append(self.scope_custom_entry)
        scope_box.append(custom_box)

        content.append(scope_box)

        # Permission type
        perm_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        perm_label = Gtk.Label(label="Permission:")
        perm_box.append(perm_label)

        self.perm_read = Gtk.CheckButton(label="Read only")
        self.perm_write = Gtk.CheckButton(label="Write only")
        self.perm_write.set_group(self.perm_read)
        self.perm_rw = Gtk.CheckButton(label="Read & Write")
        self.perm_rw.set_group(self.perm_read)

        if access_type == "read":
            self.perm_read.set_active(True)
        else:
            self.perm_rw.set_active(True)

        perm_box.append(self.perm_read)
        perm_box.append(self.perm_write)
        perm_box.append(self.perm_rw)
        content.append(perm_box)

        content.append(Gtk.Separator())

        # Bottom bar: Apply button + timer
        bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        self.apply_button = Gtk.Button(label="Apply")
        self.apply_button.add_css_class("suggested-action")
        self.apply_button.connect("clicked", self._on_apply)
        bottom.append(self.apply_button)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        bottom.append(spacer)

        self.timer_label = Gtk.Label(label=f"Timeout: {self.remaining}s")
        self.timer_label.add_css_class("dim-label")
        bottom.append(self.timer_label)

        content.append(bottom)
        self.set_content(content)

        # Start countdown
        self._timer_id = GLib.timeout_add_seconds(1, self._tick)

    def _get_app_icon(self, executable):
        """Try to find an icon for the application."""
        icon = Gtk.Image.new_from_icon_name("application-x-executable")
        icon.set_pixel_size(48)

        app_name = os.path.basename(executable)
        app_info = Gio.DesktopAppInfo.new(f"{app_name}.desktop")
        if app_info:
            gicon = app_info.get_icon()
            if gicon:
                icon.set_from_gicon(gicon)

        return icon

    def _tick(self):
        """Countdown timer tick."""
        self.remaining -= 1
        self.timer_label.set_label(f"Timeout: {self.remaining}s")

        if self.remaining <= 0:
            self._auto_deny()
            return GLib.SOURCE_REMOVE

        return GLib.SOURCE_CONTINUE

    def _auto_deny(self):
        """Auto-deny on timeout."""
        if not self.responded:
            self.responded = True
            try:
                self.client.respond_to_request(
                    self.request_id, "deny", "once", "exact", "readwrite"
                )
            except Exception:
                pass
            self.close()

    def _on_apply(self, button):
        """Handle the Apply button click."""
        if self.responded:
            return
        self.responded = True

        if self._timer_id:
            GLib.source_remove(self._timer_id)

        action = "allow" if self.allow_check.get_active() else "deny"
        duration = self.DURATIONS[self.duration_dropdown.get_selected()][1]

        if self.scope_exact.get_active():
            scope = "exact"
        elif self.scope_folder.get_active():
            scope = "folder"
        elif self.scope_recursive.get_active():
            scope = "recursive"
        elif self.scope_home.get_active():
            scope = "home"
        else:
            scope = self.scope_custom_entry.get_text()

        if self.perm_read.get_active():
            permission = "read"
        elif self.perm_write.get_active():
            permission = "write"
        else:
            permission = "readwrite"

        try:
            self.client.respond_to_request(
                self.request_id, action, duration, scope, permission
            )
        except Exception as e:
            print(f"Error responding: {e}")

        self.close()
