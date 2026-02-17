mod config;
mod event_log;
mod exclusions;
mod fanotify;
mod process_info;

use std::path::PathBuf;

use anyhow::Result;

use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Accept optional config path as first CLI argument.
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(Config::default_path);

    // Load config from file, falling back to defaults if the file is not found.
    let config = if config_path.exists() {
        Config::load(&config_path)?
    } else {
        Config::default()
    };

    // Initialize tracing with the configured log level.
    let filter = tracing_subscriber::EnvFilter::from_default_env().add_directive(
        format!("filesnitchd={}", config.general.log_level).parse()?,
    );

    tracing_subscriber::fmt().with_env_filter(filter).init();

    if !config_path.exists() {
        tracing::warn!(
            path = %config_path.display(),
            "config file not found, using defaults"
        );
    }

    tracing::info!(
        mode = %config.general.operation_mode,
        protection = %config.general.protection_mode,
        default_action = %config.general.default_action,
        prompt_timeout = config.general.prompt_timeout,
        db_path = %config.general.db_path.display(),
        "filesnitchd starting"
    );

    Ok(())
}
