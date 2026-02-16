use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;
use zvariant::Type;

pub const DBUS_BUS_NAME: &str = "org.filesnitch.Daemon";
pub const DBUS_OBJECT_PATH: &str = "/org/filesnitch/Daemon";
pub const DBUS_INTERFACE: &str = "org.filesnitch.Daemon";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Type, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Allow => write!(f, "allow"),
            Action::Deny => write!(f, "deny"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Type, PartialEq, Eq)]
pub enum PermissionKind {
    Read,
    Write,
    ReadWrite,
}

impl PermissionKind {
    pub fn allows(self, requested: PermissionKind) -> bool {
        matches!(
            (self, requested),
            (PermissionKind::ReadWrite, _)
                | (PermissionKind::Read, PermissionKind::Read)
                | (PermissionKind::Write, PermissionKind::Write)
        )
    }
}

impl fmt::Display for PermissionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermissionKind::Read => write!(f, "read"),
            PermissionKind::Write => write!(f, "write"),
            PermissionKind::ReadWrite => write!(f, "read_write"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Type, PartialEq, Eq)]
pub enum RuleScope {
    ExactFile,
    Folder,
    FolderRecursive,
    Home,
    Custom,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Type, PartialEq, Eq)]
pub enum RuleLayer {
    Home,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Type, PartialEq, Eq)]
pub enum RuleStatus {
    Active,
    Expired,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct Rule {
    pub id: i64,
    pub executable: String,
    pub path: String,
    pub scope: RuleScope,
    pub permission: PermissionKind,
    pub action: Action,
    pub layer: RuleLayer,
    pub expires_at: Option<i64>,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Rule {
    pub fn status(&self) -> RuleStatus {
        if !self.enabled {
            return RuleStatus::Disabled;
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at < now_ts() {
                return RuleStatus::Expired;
            }
        }
        RuleStatus::Active
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct NewRule {
    pub executable: String,
    pub path: String,
    pub scope: RuleScope,
    pub permission: PermissionKind,
    pub action: Action,
    pub layer: RuleLayer,
    pub expires_at: Option<i64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Type, PartialEq, Eq)]
pub enum ProtectionMode {
    ProtectEverything,
    ProtectCriticalOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[serde(default)]
pub struct DaemonConfig {
    pub protection_mode: ProtectionMode,
    pub critical_paths: Vec<String>,
    pub excluded_executables: Vec<String>,
    pub default_action_on_timeout: Action,
    pub prompt_timeout_seconds: u64,
    pub log_verbosity: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            protection_mode: ProtectionMode::ProtectEverything,
            critical_paths: vec![
                "~/.ssh/**".to_string(),
                "~/.gnupg/**".to_string(),
                "~/.aws/**".to_string(),
                "~/.kube/**".to_string(),
                "~/.bashrc".to_string(),
                "~/.zshrc".to_string(),
                "~/.profile".to_string(),
                "~/.bash_profile".to_string(),
                "~/.gitconfig".to_string(),
                "~/.config/git/**".to_string(),
                "~/.mozilla/**".to_string(),
                "~/.config/chromium/**".to_string(),
                "~/.config/google-chrome/**".to_string(),
            ],
            excluded_executables: vec![
                "/usr/bin/gpg-agent".to_string(),
                "/usr/bin/ssh-agent".to_string(),
            ],
            default_action_on_timeout: Action::Deny,
            prompt_timeout_seconds: 30,
            log_verbosity: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct PermissionRequest {
    pub request_id: String,
    pub pid: u32,
    pub app_name: String,
    pub executable: String,
    pub target_path: String,
    pub permission: PermissionKind,
    pub layer: RuleLayer,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct DecisionInput {
    pub request_id: String,
    pub action: Action,
    pub duration_seconds: i64,
    pub scope: RuleScope,
    pub permission: PermissionKind,
    pub custom_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct EventLogEntry {
    pub id: i64,
    pub timestamp: i64,
    pub pid: u32,
    pub executable: String,
    pub target_path: String,
    pub permission: PermissionKind,
    pub action: Action,
    pub rule_id: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct DaemonStatus {
    pub running: bool,
    pub protection_mode: ProtectionMode,
    pub active_rule_count: u64,
    pub pending_requests: u64,
}

pub fn now_ts() -> i64 {
    Utc::now().timestamp()
}
