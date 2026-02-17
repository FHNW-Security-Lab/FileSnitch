use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Top-level daemon configuration.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub critical_paths: CriticalPathsConfig,
    pub excluded_executables: ExcludedExecutablesConfig,
}

/// General daemon settings.
#[derive(Debug, Deserialize)]
pub struct GeneralConfig {
    pub operation_mode: OperationMode,
    pub protection_mode: ProtectionMode,
    pub default_action: DefaultAction,
    pub prompt_timeout: u32,
    pub db_path: PathBuf,
    pub log_level: String,
}

/// Whether the daemon is learning new rules or enforcing existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    Learning,
    Enforce,
}

/// Which file paths to monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    CriticalOnly,
    Everything,
}

/// Default action when no rule matches (or prompt times out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Deny,
    Allow,
}

/// Paths considered critical for monitoring.
#[derive(Debug, Deserialize)]
pub struct CriticalPathsConfig {
    pub paths: Vec<String>,
}

/// Executables excluded from monitoring.
#[derive(Debug, Deserialize)]
pub struct ExcludedExecutablesConfig {
    pub paths: Vec<PathBuf>,
}

impl Config {
    /// Load configuration from the given TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Returns the default config file path (`/etc/filesnitch/filesnitchd.toml`).
    pub fn default_path() -> PathBuf {
        PathBuf::from("/etc/filesnitch/filesnitchd.toml")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                operation_mode: OperationMode::Learning,
                protection_mode: ProtectionMode::CriticalOnly,
                default_action: DefaultAction::Deny,
                prompt_timeout: 30,
                db_path: PathBuf::from("/var/lib/filesnitchd/rules.db"),
                log_level: "info".to_string(),
            },
            critical_paths: CriticalPathsConfig {
                paths: vec![
                    ".ssh".to_string(),
                    ".gnupg".to_string(),
                    ".bashrc".to_string(),
                    ".zshrc".to_string(),
                    ".profile".to_string(),
                    ".bash_profile".to_string(),
                    ".aws".to_string(),
                    ".kube".to_string(),
                    ".gitconfig".to_string(),
                    ".config/git".to_string(),
                    ".mozilla".to_string(),
                    ".config/google-chrome".to_string(),
                    ".config/chromium".to_string(),
                    ".thunderbird".to_string(),
                    ".config/Code".to_string(),
                ],
            },
            excluded_executables: ExcludedExecutablesConfig {
                paths: vec![],
            },
        }
    }
}

impl std::fmt::Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationMode::Learning => write!(f, "learning"),
            OperationMode::Enforce => write!(f, "enforce"),
        }
    }
}

impl std::fmt::Display for ProtectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectionMode::CriticalOnly => write!(f, "critical_only"),
            ProtectionMode::Everything => write!(f, "everything"),
        }
    }
}

impl std::fmt::Display for DefaultAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultAction::Deny => write!(f, "deny"),
            DefaultAction::Allow => write!(f, "allow"),
        }
    }
}
