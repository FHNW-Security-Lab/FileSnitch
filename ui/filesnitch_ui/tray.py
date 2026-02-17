"""System tray icon using AppIndicator3 (if available)."""

import gi


def setup_tray(app):
    """Set up the system tray icon.

    Uses AppIndicator3 if available, otherwise silently skips.
    Returns the indicator object or None.
    """
    try:
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3
    except (ValueError, ImportError):
        # AppIndicator3 not available - run without tray
        return None

    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk, GLib

    # Note: AppIndicator3 uses GTK3 menus. We create a minimal GTK3-compatible
    # menu. In practice on GTK4 systems, the tray may need a different approach
    # (e.g., libayatana-appindicator or direct StatusNotifierItem via D-Bus).
    # This is a best-effort implementation.

    indicator = AppIndicator3.Indicator.new(
        "filesnitch",
        "security-high-symbolic",
        AppIndicator3.IndicatorCategory.SYSTEM_SERVICES,
    )
    indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
    indicator.set_title("FileSnitch")

    # Build menu
    menu = Gtk.Menu()

    # Open window
    open_item = Gtk.MenuItem(label="Open FileSnitch")
    open_item.connect("activate", lambda _: _activate_window(app))
    menu.append(open_item)

    menu.append(Gtk.SeparatorMenuItem())

    # Protection mode toggle
    protect_item = Gtk.CheckMenuItem(label="Protect Everything")
    protect_item.connect("toggled", lambda item: _toggle_protection(app, item))
    menu.append(protect_item)

    # Operation mode toggle
    enforce_item = Gtk.CheckMenuItem(label="Enforce Mode")
    enforce_item.connect("toggled", lambda item: _toggle_enforce(app, item))
    menu.append(enforce_item)

    menu.append(Gtk.SeparatorMenuItem())

    # Pause
    pause_item = Gtk.MenuItem(label="Pause (5 min)")
    pause_item.connect("activate", lambda _: _pause(app))
    menu.append(pause_item)

    menu.append(Gtk.SeparatorMenuItem())

    # Quit
    quit_item = Gtk.MenuItem(label="Quit")
    quit_item.connect("activate", lambda _: app.quit())
    menu.append(quit_item)

    menu.show_all()
    indicator.set_menu(menu)

    return indicator


def _activate_window(app):
    """Show or raise the main window."""
    if app.main_window:
        app.main_window.present()


def _toggle_protection(app, item):
    """Toggle protection mode."""
    if app.client:
        try:
            mode = "everything" if item.get_active() else "critical_only"
            app.client.set_config("protection_mode", mode)
        except Exception:
            pass


def _toggle_enforce(app, item):
    """Toggle operation mode."""
    if app.client:
        try:
            mode = "enforce" if item.get_active() else "learning"
            app.client.set_config("operation_mode", mode)
        except Exception:
            pass


def _pause(app):
    """Pause monitoring for 5 minutes by switching to learning mode temporarily."""
    if app.client:
        try:
            app.client.set_config("operation_mode", "learning")
            # Schedule re-enable after 5 minutes
            from gi.repository import GLib
            GLib.timeout_add_seconds(300, lambda: _unpause(app))
        except Exception:
            pass


def _unpause(app):
    """Re-enable enforce mode after pause."""
    if app.client:
        try:
            app.client.set_config("operation_mode", "enforce")
        except Exception:
            pass
    return False  # Don't repeat
