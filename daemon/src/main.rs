mod config;
mod dbus_interface;
mod decision;
mod event_log;
mod exclusions;
mod fanotify;
mod process_info;
mod rules;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use sd_notify::NotifyState;
use tokio::sync::{mpsc, RwLock};

use config::Config;
use dbus_interface::FilesnitchInterface;
use decision::{DecisionEngine, PendingRequest};
use event_log::EventLog;
use exclusions::ExclusionList;
use process_info::ProcessInfoCache;
use rules::RuleStore;

#[tokio::main]
async fn main() -> Result<()> {
    // -----------------------------------------------------------------------
    // 1. Parse config
    // -----------------------------------------------------------------------
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(Config::default_path);

    let config = if config_path.exists() {
        Config::load(&config_path)?
    } else {
        Config::default()
    };

    // -----------------------------------------------------------------------
    // 2. Initialize tracing
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // 3. Open/create SQLite database directory
    // -----------------------------------------------------------------------
    let db_path = config.general.db_path.clone();
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            tracing::info!(path = %parent.display(), "created database directory");
        }
    }

    // -----------------------------------------------------------------------
    // 4. Create shared state
    // -----------------------------------------------------------------------
    let config = Arc::new(RwLock::new(config));
    let rules = Arc::new(RuleStore::new(&db_path)?);
    let event_log = Arc::new(EventLog::new(&db_path)?);

    let exclusions = {
        let cfg = config.read().await;
        Arc::new(RwLock::new(ExclusionList::new(&cfg)))
    };

    let process_cache = Arc::new(ProcessInfoCache::new());
    let pending_requests: Arc<RwLock<HashMap<u64, PendingRequest>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // -----------------------------------------------------------------------
    // 5. Create DecisionEngine with pending notification channel
    // -----------------------------------------------------------------------
    let (pending_notify_tx, mut pending_notify_rx) = mpsc::unbounded_channel();

    let engine = Arc::new(DecisionEngine::new(
        config.clone(),
        rules.clone(),
        exclusions.clone(),
        process_cache.clone(),
        pending_requests.clone(),
        pending_notify_tx,
    ));

    // -----------------------------------------------------------------------
    // 6. Initialize fanotify (root only; otherwise D-Bus-only mode)
    // -----------------------------------------------------------------------
    let is_root = nix::unistd::geteuid().is_root();

    // Channels between the fanotify reader thread and the async event loop.
    // event_tx/event_rx: fanotify events from the reader to the decision loop.
    // response_tx/response_rx: (request_id, allow) back to the reader.
    let (event_tx, mut event_rx) = mpsc::channel(256);
    let (response_tx, response_rx) = std::sync::mpsc::channel::<(u64, bool)>();

    let _fanotify_handle = if is_root {
        match fanotify::init_fanotify() {
            Ok(fan) => {
                let handle = fanotify::spawn_event_reader(fan, event_tx, response_rx);
                tracing::info!("fanotify event reader started");
                Some(handle)
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize fanotify");
                return Err(e);
            }
        }
    } else {
        tracing::warn!(
            "not running as root, fanotify disabled -- running in D-Bus-only mode for development"
        );
        None
    };

    // -----------------------------------------------------------------------
    // 7-8. Set up D-Bus connection
    // -----------------------------------------------------------------------
    let iface = FilesnitchInterface {
        engine: engine.clone(),
        config: config.clone(),
        rules: rules.clone(),
        event_log: event_log.clone(),
    };

    let dbus_conn = zbus::connection::Builder::system()?
        .name("org.filesnitch.Daemon")?
        .serve_at("/org/filesnitch/Daemon", iface)?
        .build()
        .await?;

    tracing::info!("D-Bus interface registered on system bus as org.filesnitch.Daemon");

    // -----------------------------------------------------------------------
    // 9. sd_notify ready
    // -----------------------------------------------------------------------
    let _ = sd_notify::notify(true, &[NotifyState::Ready]);
    tracing::info!("daemon ready (sd_notify sent)");

    // -----------------------------------------------------------------------
    // 10. Spawn main event loop
    // -----------------------------------------------------------------------
    let engine_loop = engine.clone();
    let event_log_loop = event_log.clone();
    let process_cache_loop = process_cache.clone();

    let event_loop_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let request_id = event.request_id;
            let pid = event.pid;
            let target_path = event.target_path.clone();
            let access_type_str = match event.access_type {
                fanotify::AccessType::Read => "read",
                fanotify::AccessType::Write => "write",
            };

            // Resolve process info for logging (best effort).
            let executable = process_cache_loop
                .resolve(pid)
                .map(|info| info.executable)
                .unwrap_or_else(|_| PathBuf::from("<unknown>"));

            // Call the decision engine (may block on user prompt with timeout).
            let (allowed, reason) = engine_loop.decide(&event).await;

            // Send the response back to the fanotify reader thread.
            if response_tx.send((request_id, allowed)).is_err() {
                tracing::error!(
                    request_id,
                    "fanotify response channel closed, cannot send response"
                );
                break;
            }

            // Extract rule_id from reason if it matches "rule:<id>".
            let rule_id = if reason.starts_with("rule:") {
                reason[5..].parse::<i64>().ok()
            } else {
                None
            };

            let decision_str = if allowed { "allow" } else { "deny" };

            // Log the event to the database.
            if let Err(e) = event_log_loop.log_event(
                pid,
                &executable,
                &target_path,
                access_type_str,
                decision_str,
                &reason,
                rule_id,
            ) {
                tracing::error!(error = %e, "failed to log event");
            }

            tracing::debug!(
                request_id,
                pid,
                path = %target_path.display(),
                decision = decision_str,
                reason = %reason,
                "event processed"
            );
        }

        tracing::info!("event loop exiting");
    });

    // -----------------------------------------------------------------------
    // Spawn D-Bus signal emitter for pending permission requests
    // -----------------------------------------------------------------------
    let dbus_conn_signals = dbus_conn.clone();

    let signal_emitter_handle = tokio::spawn(async move {
        let object_server = dbus_conn_signals.object_server();
        while let Some((request_id, pid, executable, target_path, access_type, app_name, timestamp)) =
            pending_notify_rx.recv().await
        {
            let iface_ref = match object_server
                .interface::<_, FilesnitchInterface>("/org/filesnitch/Daemon")
                .await
            {
                Ok(iface_ref) => iface_ref,
                Err(e) => {
                    tracing::error!(error = %e, "failed to get D-Bus interface reference for signal");
                    continue;
                }
            };

            let emitter = iface_ref.signal_emitter();
            if let Err(e) = FilesnitchInterface::permission_request(
                &emitter,
                request_id,
                pid as u32,
                &executable,
                &target_path,
                &access_type,
                &app_name,
                timestamp,
            )
            .await
            {
                tracing::error!(
                    error = %e,
                    request_id,
                    "failed to emit PermissionRequest D-Bus signal"
                );
            } else {
                tracing::debug!(
                    request_id,
                    app = %app_name,
                    path = %target_path,
                    "emitted PermissionRequest D-Bus signal"
                );
            }
        }

        tracing::info!("D-Bus signal emitter exiting");
    });

    // -----------------------------------------------------------------------
    // 11. Spawn watchdog task
    // -----------------------------------------------------------------------
    let watchdog_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let _ = sd_notify::notify(true, &[NotifyState::Watchdog]);
        }
    });

    // -----------------------------------------------------------------------
    // 12. Spawn cleanup task
    // -----------------------------------------------------------------------
    let rules_cleanup = rules.clone();
    let process_cache_cleanup = process_cache.clone();

    let cleanup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = rules_cleanup.cleanup_expired() {
                tracing::error!(error = %e, "failed to cleanup expired rules");
            }
            process_cache_cleanup.cleanup();
            tracing::debug!("periodic cleanup completed");
        }
    });

    // -----------------------------------------------------------------------
    // 13. Handle SIGTERM/SIGINT
    // -----------------------------------------------------------------------
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM, shutting down");
        }
        _ = sigint.recv() => {
            tracing::info!("received SIGINT, shutting down");
        }
        _ = event_loop_handle => {
            tracing::info!("event loop exited, shutting down");
        }
    }

    // Abort background tasks.
    watchdog_handle.abort();
    cleanup_handle.abort();
    signal_emitter_handle.abort();

    // Dropping the fanotify handle causes the kernel to auto-allow
    // any pending permission events.
    drop(_fanotify_handle);

    tracing::info!("filesnitchd stopped");
    Ok(())
}
