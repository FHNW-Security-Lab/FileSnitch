use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;
use zbus::object_server::SignalEmitter;

use crate::config::{Config, DefaultAction, OperationMode, ProtectionMode};
use crate::decision::{DecisionEngine, UserDecision};
use crate::event_log::{Event, EventLog};
use crate::rules::{Action, Permission, Rule, RuleStore};

/// D-Bus interface implementation for the FileSnitch daemon.
///
/// Exposes rule management, event log queries, configuration, and
/// permission-request handling over the system bus at
/// `org.filesnitch.Daemon`.
pub struct FilesnitchInterface {
    pub engine: Arc<DecisionEngine>,
    pub config: Arc<RwLock<Config>>,
    pub rules: Arc<RuleStore>,
    pub event_log: Arc<EventLog>,
}

// ---------------------------------------------------------------------------
// Helper: Rule -> D-Bus dict
// ---------------------------------------------------------------------------

fn rule_to_dict(rule: &Rule) -> HashMap<String, zbus::zvariant::OwnedValue> {
    let mut map = HashMap::new();
    map.insert(
        "id".to_string(),
        zbus::zvariant::Value::from(rule.id as u64).try_into().unwrap(),
    );
    map.insert(
        "executable".to_string(),
        zbus::zvariant::Value::from(rule.executable.to_string_lossy().as_ref())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "path_pattern".to_string(),
        zbus::zvariant::Value::from(rule.path_pattern.as_str())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "permission".to_string(),
        zbus::zvariant::Value::from(rule.permission.to_string().as_str())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "action".to_string(),
        zbus::zvariant::Value::from(rule.action.to_string().as_str())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "is_critical".to_string(),
        zbus::zvariant::Value::from(rule.is_critical).try_into().unwrap(),
    );
    map.insert(
        "created_at".to_string(),
        zbus::zvariant::Value::from(rule.created_at.to_rfc3339().as_str())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "expires_at".to_string(),
        zbus::zvariant::Value::from(
            rule.expires_at
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
                .as_str(),
        )
        .try_to_owned()
        .unwrap(),
    );
    map.insert(
        "enabled".to_string(),
        zbus::zvariant::Value::from(rule.enabled).try_into().unwrap(),
    );
    map.insert(
        "hit_count".to_string(),
        zbus::zvariant::Value::from(rule.hit_count).try_into().unwrap(),
    );
    map.insert(
        "last_hit_at".to_string(),
        zbus::zvariant::Value::from(
            rule.last_hit_at
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
                .as_str(),
        )
        .try_to_owned()
        .unwrap(),
    );
    map
}

// ---------------------------------------------------------------------------
// Helper: Event -> D-Bus dict
// ---------------------------------------------------------------------------

fn event_to_dict(event: &Event) -> HashMap<String, zbus::zvariant::OwnedValue> {
    let mut map = HashMap::new();
    map.insert(
        "id".to_string(),
        zbus::zvariant::Value::from(event.id as u64).try_into().unwrap(),
    );
    map.insert(
        "timestamp".to_string(),
        zbus::zvariant::Value::from(event.timestamp.to_rfc3339().as_str())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "pid".to_string(),
        zbus::zvariant::Value::from(event.pid as u32).try_into().unwrap(),
    );
    map.insert(
        "executable".to_string(),
        zbus::zvariant::Value::from(event.executable.to_string_lossy().as_ref())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "target_path".to_string(),
        zbus::zvariant::Value::from(event.target_path.to_string_lossy().as_ref())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "access_type".to_string(),
        zbus::zvariant::Value::from(event.access_type.as_str())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "decision".to_string(),
        zbus::zvariant::Value::from(event.decision.as_str())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "reason".to_string(),
        zbus::zvariant::Value::from(event.reason.as_str())
            .try_to_owned()
            .unwrap(),
    );
    map.insert(
        "rule_id".to_string(),
        zbus::zvariant::Value::from(event.rule_id.unwrap_or(0) as u64)
            .try_into()
            .unwrap(),
    );
    map
}

// ---------------------------------------------------------------------------
// Helper: extract a string field from a D-Bus variant dict
// ---------------------------------------------------------------------------

fn get_str_field<'a>(
    dict: &'a HashMap<String, zbus::zvariant::Value<'_>>,
    key: &str,
) -> Result<&'a str, zbus::fdo::Error> {
    dict.get(key)
        .and_then(|v| <&str>::try_from(v).ok())
        .ok_or_else(|| {
            zbus::fdo::Error::InvalidArgs(format!("missing or invalid string field: {key}"))
        })
}

fn get_bool_field(
    dict: &HashMap<String, zbus::zvariant::Value<'_>>,
    key: &str,
) -> Option<bool> {
    dict.get(key).and_then(|v| bool::try_from(v).ok())
}

// ---------------------------------------------------------------------------
// D-Bus interface implementation
// ---------------------------------------------------------------------------

#[zbus::interface(name = "org.filesnitch.Daemon")]
impl FilesnitchInterface {
    // -----------------------------------------------------------------------
    // Methods
    // -----------------------------------------------------------------------

    /// Respond to a pending permission request from the UI or CLI.
    ///
    /// Looks up the pending request by `request_id` and sends the user's
    /// decision through the oneshot channel so the decision engine can
    /// complete the fanotify response.
    async fn respond_to_request(
        &self,
        request_id: u64,
        action: &str,
        duration: &str,
        path_scope: &str,
        permission: &str,
    ) -> zbus::fdo::Result<()> {
        let action_enum = match action {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            _ => {
                return Err(zbus::fdo::Error::InvalidArgs(
                    "action must be 'allow' or 'deny'".to_string(),
                ))
            }
        };

        let decision = UserDecision {
            action: action_enum,
            duration: duration.to_string(),
            path_scope: path_scope.to_string(),
            permission: permission.to_string(),
        };

        let mut pending = self.engine.pending_requests.write().await;
        let request = pending.remove(&request_id).ok_or_else(|| {
            zbus::fdo::Error::Failed(format!("no pending request with id {request_id}"))
        })?;

        request.response_tx.send(decision).map_err(|_| {
            zbus::fdo::Error::Failed("failed to send decision: receiver dropped".to_string())
        })
    }

    /// List all rules, optionally filtered by an `app` key in the filter dict.
    async fn list_rules(
        &self,
        filter: HashMap<String, zbus::zvariant::Value<'_>>,
    ) -> zbus::fdo::Result<Vec<HashMap<String, zbus::zvariant::OwnedValue>>> {
        let app_filter = filter
            .get("app")
            .and_then(|v| <&str>::try_from(v).ok())
            .map(|s| s.to_string());

        let rules = self
            .rules
            .list_rules(app_filter.as_deref())
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let result: Vec<HashMap<String, zbus::zvariant::OwnedValue>> =
            rules.iter().map(rule_to_dict).collect();

        Ok(result)
    }

    /// Add a new rule from a D-Bus variant dict.
    ///
    /// Required fields: `executable`, `path_pattern`, `permission`, `action`.
    /// Optional fields: `is_critical` (bool, defaults to false).
    async fn add_rule(
        &self,
        rule: HashMap<String, zbus::zvariant::Value<'_>>,
    ) -> zbus::fdo::Result<u64> {
        let executable = get_str_field(&rule, "executable")?;
        let path_pattern = get_str_field(&rule, "path_pattern")?;
        let permission_str = get_str_field(&rule, "permission")?;
        let action_str = get_str_field(&rule, "action")?;
        let is_critical = get_bool_field(&rule, "is_critical").unwrap_or(false);

        let permission = match permission_str {
            "read" => Permission::Read,
            "write" => Permission::Write,
            "read_write" => Permission::ReadWrite,
            _ => {
                return Err(zbus::fdo::Error::InvalidArgs(
                    "permission must be 'read', 'write', or 'read_write'".to_string(),
                ))
            }
        };

        let action = match action_str {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            _ => {
                return Err(zbus::fdo::Error::InvalidArgs(
                    "action must be 'allow' or 'deny'".to_string(),
                ))
            }
        };

        let id = self
            .rules
            .add_rule(
                PathBuf::from(executable),
                path_pattern.to_string(),
                permission,
                action,
                is_critical,
                None,
            )
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(id as u64)
    }

    /// Delete a rule by its ID.
    async fn delete_rule(&self, rule_id: u64) -> zbus::fdo::Result<()> {
        self.rules
            .delete_rule(rule_id as i64)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Export all rules as a JSON string.
    async fn export_rules(&self) -> zbus::fdo::Result<String> {
        self.rules
            .export_json()
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Import rules from a JSON string. Returns the number of rules imported.
    async fn import_rules(&self, json: &str) -> zbus::fdo::Result<u32> {
        self.rules
            .import_json(json)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Get recent events, optionally filtered by `app` and/or `path` keys.
    async fn get_recent_events(
        &self,
        count: u32,
        filter: HashMap<String, zbus::zvariant::Value<'_>>,
    ) -> zbus::fdo::Result<Vec<HashMap<String, zbus::zvariant::OwnedValue>>> {
        let app_filter = filter
            .get("app")
            .and_then(|v| <&str>::try_from(v).ok())
            .map(|s| s.to_string());

        let path_filter = filter
            .get("path")
            .and_then(|v| <&str>::try_from(v).ok())
            .map(|s| s.to_string());

        let events = self
            .event_log
            .get_recent(count, app_filter.as_deref(), path_filter.as_deref())
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let result: Vec<HashMap<String, zbus::zvariant::OwnedValue>> =
            events.iter().map(event_to_dict).collect();

        Ok(result)
    }

    /// Get the current daemon configuration as a D-Bus dict.
    async fn get_config(
        &self,
    ) -> zbus::fdo::Result<HashMap<String, zbus::zvariant::OwnedValue>> {
        let config = self.config.read().await;
        let mut map = HashMap::new();
        map.insert(
            "operation_mode".to_string(),
            zbus::zvariant::Value::from(config.general.operation_mode.to_string().as_str())
                .try_to_owned()
                .unwrap(),
        );
        map.insert(
            "protection_mode".to_string(),
            zbus::zvariant::Value::from(config.general.protection_mode.to_string().as_str())
                .try_to_owned()
                .unwrap(),
        );
        map.insert(
            "default_action".to_string(),
            zbus::zvariant::Value::from(config.general.default_action.to_string().as_str())
                .try_to_owned()
                .unwrap(),
        );
        map.insert(
            "prompt_timeout".to_string(),
            zbus::zvariant::Value::from(config.general.prompt_timeout)
                .try_into()
                .unwrap(),
        );
        Ok(map)
    }

    /// Set a configuration value by key.
    ///
    /// Supported keys: `operation_mode`, `protection_mode`,
    /// `default_action`, `prompt_timeout`.
    async fn set_config(&self, key: &str, value: &str) -> zbus::fdo::Result<()> {
        let mut config = self.config.write().await;
        match key {
            "operation_mode" => {
                config.general.operation_mode = match value {
                    "learning" => OperationMode::Learning,
                    "enforce" => OperationMode::Enforce,
                    _ => {
                        return Err(zbus::fdo::Error::InvalidArgs(
                            "operation_mode must be 'learning' or 'enforce'".to_string(),
                        ))
                    }
                };
            }
            "protection_mode" => {
                config.general.protection_mode = match value {
                    "critical_only" => ProtectionMode::CriticalOnly,
                    "everything" => ProtectionMode::Everything,
                    _ => {
                        return Err(zbus::fdo::Error::InvalidArgs(
                            "protection_mode must be 'critical_only' or 'everything'".to_string(),
                        ))
                    }
                };
            }
            "default_action" => {
                config.general.default_action = match value {
                    "deny" => DefaultAction::Deny,
                    "allow" => DefaultAction::Allow,
                    _ => {
                        return Err(zbus::fdo::Error::InvalidArgs(
                            "default_action must be 'deny' or 'allow'".to_string(),
                        ))
                    }
                };
            }
            "prompt_timeout" => {
                config.general.prompt_timeout = value.parse::<u32>().map_err(|_| {
                    zbus::fdo::Error::InvalidArgs(
                        "prompt_timeout must be a positive integer".to_string(),
                    )
                })?;
            }
            _ => {
                return Err(zbus::fdo::Error::InvalidArgs(format!(
                    "unknown config key: {key}"
                )));
            }
        }
        Ok(())
    }

    /// Get daemon status: operation mode, protection mode, and pending
    /// request count.
    async fn get_status(
        &self,
    ) -> zbus::fdo::Result<HashMap<String, zbus::zvariant::OwnedValue>> {
        let config = self.config.read().await;
        let pending_count = self.engine.pending_requests.read().await.len();

        let mut map = HashMap::new();
        map.insert(
            "operation_mode".to_string(),
            zbus::zvariant::Value::from(config.general.operation_mode.to_string().as_str())
                .try_to_owned()
                .unwrap(),
        );
        map.insert(
            "protection_mode".to_string(),
            zbus::zvariant::Value::from(config.general.protection_mode.to_string().as_str())
                .try_to_owned()
                .unwrap(),
        );
        map.insert(
            "pending_requests".to_string(),
            zbus::zvariant::Value::from(pending_count as u64)
                .try_into()
                .unwrap(),
        );
        Ok(map)
    }

    /// Get the list of critical paths from the configuration.
    async fn get_critical_paths(&self) -> zbus::fdo::Result<Vec<String>> {
        let config = self.config.read().await;
        Ok(config.critical_paths.paths.clone())
    }

    /// Add a path to the critical paths list (if not already present).
    async fn add_critical_path(&self, path: &str) -> zbus::fdo::Result<()> {
        let mut config = self.config.write().await;
        if !config.critical_paths.paths.contains(&path.to_string()) {
            config.critical_paths.paths.push(path.to_string());
        }
        Ok(())
    }

    /// Remove a path from the critical paths list.
    async fn remove_critical_path(&self, path: &str) -> zbus::fdo::Result<()> {
        let mut config = self.config.write().await;
        config.critical_paths.paths.retain(|p| p != path);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Signals
    // -----------------------------------------------------------------------

    /// Emitted when a permission request needs user input.
    #[zbus(signal)]
    async fn permission_request(
        emitter: &SignalEmitter<'_>,
        request_id: u64,
        pid: u32,
        executable: &str,
        target_path: &str,
        access_type: &str,
        app_name: &str,
        timestamp: u64,
    ) -> zbus::Result<()>;

    /// Emitted when a rule is added, modified, or deleted.
    #[zbus(signal)]
    async fn rule_changed(
        emitter: &SignalEmitter<'_>,
        rule_id: u64,
        change_type: &str,
    ) -> zbus::Result<()>;

    /// Emitted when an access-decision event is logged.
    #[zbus(signal)]
    async fn event_logged(
        emitter: &SignalEmitter<'_>,
        event: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::Result<()>;
}
