use crate::models::DaemonConfig;
use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/filesnitch/config.toml";

pub fn load_config(path: Option<&Path>) -> anyhow::Result<DaemonConfig> {
    let path = path.unwrap_or(Path::new(DEFAULT_CONFIG_PATH));
    if !path.exists() {
        return Ok(DaemonConfig::default());
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let config: DaemonConfig = toml::from_str(&contents)
        .with_context(|| format!("failed to parse config {}", path.display()))?;
    Ok(config)
}

pub fn save_config(path: Option<&Path>, config: &DaemonConfig) -> anyhow::Result<PathBuf> {
    let path = path.unwrap_or(Path::new(DEFAULT_CONFIG_PATH));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config dir {}", parent.display()))?;
    }
    let content = toml::to_string_pretty(config).context("failed to encode config toml")?;
    fs::write(path, content)
        .with_context(|| format!("failed to write config {}", path.display()))?;
    Ok(path.to_path_buf())
}
