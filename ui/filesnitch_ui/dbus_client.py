"""D-Bus client for the UI - wraps shared client."""

from filesnitch_dbus.client import FilesnitchClient


def get_client():
    """Get a FilesnitchClient instance."""
    return FilesnitchClient()
