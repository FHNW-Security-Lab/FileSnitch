"""D-Bus client proxy for filesnitchd."""

from dasbus.connection import SystemMessageBus
from dasbus.identifier import DBusServiceIdentifier

FILESNITCH_NAMESPACE = ("org", "filesnitch", "Daemon")

FILESNITCH = DBusServiceIdentifier(
    namespace=FILESNITCH_NAMESPACE,
    message_bus=SystemMessageBus(),
)


class FilesnitchClient:
    """Client for the filesnitchd D-Bus interface.

    Wraps the org.filesnitch.Daemon D-Bus interface exposed by filesnitchd
    on the system bus.  All D-Bus methods are available as regular Python
    methods, and signals can be subscribed to with ``on_*`` helpers.
    """

    def __init__(self):
        self._proxy = FILESNITCH.get_proxy()

    @property
    def proxy(self):
        """Return the raw dasbus proxy for advanced usage."""
        return self._proxy

    # --- Permission decisions ---

    def respond_to_request(self, request_id, action, duration, path_scope, permission):
        """Respond to a pending permission request.

        Args:
            request_id: Unique ID of the pending request (u64).
            action: ``"allow"`` or ``"deny"``.
            duration: Duration string (e.g. ``"once"``, ``"session"``, ``"forever"``).
            path_scope: Scope of the path to which the rule applies.
            permission: Permission type (``"read"``, ``"write"``, ``"read_write"``).
        """
        self._proxy.RespondToRequest(request_id, action, duration, path_scope, permission)

    # --- Rules ---

    def list_rules(self, filter_dict=None):
        """List all rules, optionally filtered.

        Args:
            filter_dict: Optional dict with filter keys (e.g. ``{"app": "vim"}``).

        Returns:
            List of rule dicts.
        """
        return self._proxy.ListRules(filter_dict or {})

    def add_rule(self, rule_dict):
        """Add a new rule.

        Args:
            rule_dict: Dict with required keys ``executable``, ``path_pattern``,
                ``permission``, ``action``, and optional ``is_critical``.

        Returns:
            The ID of the newly created rule (u64).
        """
        return self._proxy.AddRule(rule_dict)

    def delete_rule(self, rule_id):
        """Delete a rule by ID.

        Args:
            rule_id: The rule ID to delete.
        """
        self._proxy.DeleteRule(rule_id)

    def export_rules(self):
        """Export all rules as a JSON string.

        Returns:
            JSON string of exported rules.
        """
        return self._proxy.ExportRules()

    def import_rules(self, json_str):
        """Import rules from a JSON string.

        Args:
            json_str: JSON string containing rules to import.

        Returns:
            Number of rules imported (u32).
        """
        return self._proxy.ImportRules(json_str)

    # --- Events ---

    def get_recent_events(self, count=50, filter_dict=None):
        """Get recent access-decision events.

        Args:
            count: Maximum number of events to return.
            filter_dict: Optional dict with filter keys (e.g. ``{"app": "...", "path": "..."}``)

        Returns:
            List of event dicts.
        """
        return self._proxy.GetRecentEvents(count, filter_dict or {})

    # --- Config ---

    def get_config(self):
        """Get daemon configuration.

        Returns:
            Dict with keys ``operation_mode``, ``protection_mode``,
            ``default_action``, ``prompt_timeout``.
        """
        return self._proxy.GetConfig()

    def set_config(self, key, value):
        """Set a configuration value.

        Args:
            key: Config key (``operation_mode``, ``protection_mode``,
                ``default_action``, ``prompt_timeout``).
            value: New value as a string.
        """
        self._proxy.SetConfig(key, str(value))

    # --- Status ---

    def get_status(self):
        """Get daemon status.

        Returns:
            Dict with keys ``operation_mode``, ``protection_mode``,
            ``pending_requests``.
        """
        return self._proxy.GetStatus()

    # --- Critical paths ---

    def get_critical_paths(self):
        """Get the list of critical paths.

        Returns:
            List of path strings.
        """
        return self._proxy.GetCriticalPaths()

    def add_critical_path(self, path):
        """Add a path to the critical paths list.

        Args:
            path: Filesystem path to protect.
        """
        self._proxy.AddCriticalPath(path)

    def remove_critical_path(self, path):
        """Remove a path from the critical paths list.

        Args:
            path: Filesystem path to stop protecting.
        """
        self._proxy.RemoveCriticalPath(path)

    # --- Signals ---

    def on_permission_request(self, callback):
        """Subscribe to PermissionRequest signals.

        The callback receives:
            (request_id: int, pid: int, executable: str, target_path: str,
             access_type: str, app_name: str, timestamp: int)
        """
        self._proxy.PermissionRequest.connect(callback)

    def on_rule_changed(self, callback):
        """Subscribe to RuleChanged signals.

        The callback receives:
            (rule_id: int, change_type: str)
        """
        self._proxy.RuleChanged.connect(callback)

    def on_event_logged(self, callback):
        """Subscribe to EventLogged signals.

        The callback receives:
            (event: dict)
        """
        self._proxy.EventLogged.connect(callback)
