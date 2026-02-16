use crate::models::{
    DaemonConfig, DaemonStatus, DecisionInput, EventLogEntry, NewRule,
    PermissionRequest as FsPermissionRequest, Rule,
};

#[zbus::proxy(
    interface = "org.filesnitch.Daemon",
    default_service = "org.filesnitch.Daemon",
    default_path = "/org/filesnitch/Daemon",
    gen_blocking = true
)]
pub trait FileSnitch {
    fn status(&self) -> zbus::Result<DaemonStatus>;
    fn list_rules(&self) -> zbus::Result<Vec<Rule>>;
    fn add_rule(&self, rule: NewRule) -> zbus::Result<Rule>;
    fn update_rule(&self, rule: Rule) -> zbus::Result<bool>;
    fn delete_rule(&self, id: i64) -> zbus::Result<bool>;
    fn toggle_rule(&self, id: i64, enabled: bool) -> zbus::Result<bool>;
    fn list_events(&self, limit: u32) -> zbus::Result<Vec<EventLogEntry>>;
    fn get_config(&self) -> zbus::Result<DaemonConfig>;
    fn set_config(&self, config: DaemonConfig) -> zbus::Result<bool>;
    fn submit_decision(&self, decision: DecisionInput) -> zbus::Result<bool>;
    fn export_rules(&self) -> zbus::Result<String>;
    fn import_rules(&self, data: String) -> zbus::Result<u32>;

    #[zbus(signal)]
    fn permission_request(&self, request: FsPermissionRequest) -> zbus::Result<()>;

    #[zbus(signal)]
    fn event_logged(&self, event: EventLogEntry) -> zbus::Result<()>;

    #[zbus(signal)]
    fn config_changed(&self, config: DaemonConfig) -> zbus::Result<()>;

    #[zbus(signal)]
    fn rule_changed(&self, rule: Rule) -> zbus::Result<()>;
}
