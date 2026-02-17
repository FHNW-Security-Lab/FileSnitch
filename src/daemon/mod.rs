use crate::config::{load_config, save_config};
use crate::db::Database;
use crate::fanotify::{FanotifyMonitor, KernelEvent};
use crate::matcher::{find_matching_rule, select_protection_layer};
use crate::models::{
    Action, DBUS_BUS_NAME, DBUS_OBJECT_PATH, DaemonConfig, DaemonStatus, DecisionInput, EventLogEntry,
    NewRule, PermissionRequest, Rule, RuleScope, now_ts,
};
use anyhow::{Context, anyhow};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{error, info, warn};
use zbus::{Connection, ConnectionBuilder, SignalContext, interface};

const DEFAULT_DB_PATH: &str = "/var/lib/filesnitch/filesnitch.db";
const MAX_PENDING_REQUESTS: usize = 64;

#[derive(Debug, Clone)]
pub struct DaemonOpts {
    pub config_path: Option<PathBuf>,
    pub db_path: PathBuf,
    pub home_mount_path: PathBuf,
}

impl Default for DaemonOpts {
    fn default() -> Self {
        Self {
            config_path: None,
            db_path: PathBuf::from(DEFAULT_DB_PATH),
            home_mount_path: PathBuf::from("/home"),
        }
    }
}

struct PendingRequest {
    request: PermissionRequest,
    event_fd: i32,
}

pub struct DaemonCore {
    db: Arc<Database>,
    config_path: Option<PathBuf>,
    config: RwLock<DaemonConfig>,
    fanotify: Arc<FanotifyMonitor>,
    pending: Mutex<HashMap<String, PendingRequest>>,
    home_mount_path: PathBuf,
}

impl DaemonCore {
    async fn status(&self) -> anyhow::Result<DaemonStatus> {
        let cfg = self.config.read().await.clone();
        let pending = self.pending.lock().await.len() as u64;
        let active_rules = self.db.count_active_rules()?;
        Ok(DaemonStatus {
            running: true,
            protection_mode: cfg.protection_mode,
            active_rule_count: active_rules,
            pending_requests: pending,
        })
    }

    async fn list_rules(&self) -> anyhow::Result<Vec<Rule>> {
        self.db.list_rules()
    }

    async fn add_rule(&self, rule: NewRule) -> anyhow::Result<Rule> {
        self.db.add_rule(rule)
    }

    async fn update_rule(&self, rule: &Rule) -> anyhow::Result<()> {
        self.db.update_rule(rule)
    }

    async fn delete_rule(&self, id: i64) -> anyhow::Result<()> {
        self.db.delete_rule(id)
    }

    async fn toggle_rule(&self, id: i64, enabled: bool) -> anyhow::Result<()> {
        self.db.toggle_rule(id, enabled)
    }

    async fn list_events(&self, limit: u32) -> anyhow::Result<Vec<EventLogEntry>> {
        self.db.list_events(limit)
    }

    async fn get_config(&self) -> DaemonConfig {
        self.config.read().await.clone()
    }

    async fn set_config(&self, config: DaemonConfig) -> anyhow::Result<()> {
        save_config(self.config_path.as_deref(), &config)?;
        *self.config.write().await = config;
        Ok(())
    }

    async fn export_rules(&self) -> anyhow::Result<String> {
        let rules = self.db.list_rules()?;
        Ok(toml::to_string_pretty(&rules)?)
    }

    async fn import_rules(&self, data: &str) -> anyhow::Result<u32> {
        let parsed: Vec<Rule> = toml::from_str(data)?;
        let mut imported = 0u32;
        for rule in parsed {
            let _ = self.db.add_rule(NewRule {
                executable: rule.executable,
                path: rule.path,
                scope: rule.scope,
                permission: rule.permission,
                action: rule.action,
                layer: rule.layer,
                expires_at: rule.expires_at,
                enabled: rule.enabled,
            })?;
            imported += 1;
        }
        Ok(imported)
    }

    async fn submit_decision(&self, decision: DecisionInput) -> anyhow::Result<bool> {
        let pending = {
            let mut map = self.pending.lock().await;
            map.remove(&decision.request_id)
        };

        let Some(pending) = pending else {
            return Ok(false);
        };

        let allow = matches!(decision.action, Action::Allow);
        self.fanotify.respond(pending.event_fd, allow)?;

        let mut generated_rule_id = None;
        if decision.duration_seconds != 0 {
            let rule_path =
                rule_path_from_decision(&pending.request, &decision, &self.home_mount_path);
            let expires_at = if decision.duration_seconds < 0 {
                None
            } else {
                Some(now_ts() + decision.duration_seconds)
            };
            let new_rule = NewRule {
                executable: pending.request.executable.clone(),
                path: rule_path,
                scope: decision.scope,
                permission: decision.permission,
                action: decision.action,
                layer: pending.request.layer,
                expires_at,
                enabled: true,
            };
            let created = self.db.add_rule(new_rule)?;
            generated_rule_id = Some(created.id);
        }

        self.log_event(
            &pending.request,
            decision.action,
            generated_rule_id,
            "user decision".to_string(),
        )
        .await?;
        Ok(true)
    }

    async fn timeout_pending(&self, request_id: String) -> anyhow::Result<()> {
        let pending = {
            let mut map = self.pending.lock().await;
            map.remove(&request_id)
        };

        if let Some(pending) = pending {
            let cfg = self.config.read().await.clone();
            let allow = matches!(cfg.default_action_on_timeout, Action::Allow);
            self.fanotify.respond(pending.event_fd, allow)?;
            self
                .log_event(
                    &pending.request,
                    cfg.default_action_on_timeout,
                    None,
                    "timeout default action".to_string(),
                )
                .await?;
        }
        Ok(())
    }

    async fn handle_kernel_event(self: &Arc<Self>, connection: &Connection, event: KernelEvent) -> anyhow::Result<()> {
        let Some(actor_uid) = read_uid_for_pid(event.pid) else {
            // If we cannot resolve process ownership, fail-open to avoid system stalls.
            self.fanotify.respond(event.event_fd, true)?;
            return Ok(());
        };

        // Never gate system/service accounts. This prevents boot/login freezes.
        if actor_uid < 1000 {
            self.fanotify.respond(event.event_fd, true)?;
            return Ok(());
        }

        let actor_home = home_dir_for_uid(actor_uid, &self.home_mount_path)
            .unwrap_or_else(|| self.home_mount_path.join(actor_uid.to_string()));
        let executable = read_executable_for_pid(event.pid);
        let app_name = Path::new(&executable)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| executable.clone());

        let cfg = self.config.read().await.clone();
        if cfg.excluded_executables.iter().any(|e| e == &executable) {
            self.fanotify.respond(event.event_fd, true)?;
            return Ok(());
        }
        if should_bypass_for_desktop_stability(&executable) {
            self.fanotify.respond(event.event_fd, true)?;
            return Ok(());
        }

        // Only enforce interactive permission gating when a frontend can actually answer.
        // This avoids deadlocking desktop/login flows during boot or unattended operation.
        if !has_interactive_frontend() {
            self.fanotify.respond(event.event_fd, true)?;
            let layer_for_log = select_protection_layer(
                &cfg,
                &event.target_path,
                &self.home_mount_path,
                &actor_home,
            )
            .unwrap_or(crate::models::RuleLayer::Home);
            let request = PermissionRequest {
                request_id: "no-frontend".to_string(),
                pid: event.pid,
                app_name,
                executable,
                target_path: event.target_path,
                permission: event.permission,
                layer: layer_for_log,
                timestamp: now_ts(),
            };
            self.log_event(
                &request,
                Action::Allow,
                None,
                "no interactive frontend connected; fail-open".to_string(),
            )
            .await?;
            return Ok(());
        }

        let Some(layer) = select_protection_layer(
            &cfg,
            &event.target_path,
            &self.home_mount_path,
            &actor_home,
        ) else {
            self.fanotify.respond(event.event_fd, true)?;
            return Ok(());
        };

        let rules = self.db.list_rules()?;
        if let Some(rule) = find_matching_rule(
            &rules,
            &executable,
            &event.target_path,
            event.permission,
            layer,
            &self.home_mount_path,
            &actor_home,
        ) {
            let allow = matches!(rule.action, Action::Allow);
            self.fanotify.respond(event.event_fd, allow)?;
            let request = PermissionRequest {
                request_id: "matched-rule".to_string(),
                pid: event.pid,
                app_name,
                executable,
                target_path: event.target_path,
                permission: event.permission,
                layer,
                timestamp: now_ts(),
            };
            self.log_event(&request, rule.action, Some(rule.id), "matched rule".to_string())
                .await?;
            return Ok(());
        }

        let request = PermissionRequest {
            request_id: next_request_id(),
            pid: event.pid,
            app_name,
            executable,
            target_path: event.target_path,
            permission: event.permission,
            layer,
            timestamp: now_ts(),
        };

        {
            let mut map = self.pending.lock().await;
            if map.len() >= MAX_PENDING_REQUESTS {
                drop(map);
                self.fanotify.respond(event.event_fd, true)?;
                self.log_event(
                    &request,
                    Action::Allow,
                    None,
                    format!(
                        "pending queue backpressure (>{MAX_PENDING_REQUESTS}), fail-open"
                    ),
                )
                .await?;
                return Ok(());
            }
            map.insert(
                request.request_id.clone(),
                PendingRequest {
                    request: request.clone(),
                    event_fd: event.event_fd,
                },
            );
        }

        let ctxt = SignalContext::new(connection, DBUS_OBJECT_PATH)?;
        FileSnitchDbus::permission_request(&ctxt, request.clone()).await?;

        let timeout = cfg.prompt_timeout_seconds;
        let request_id = request.request_id.clone();
        let core = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(timeout)).await;
            if let Err(err) = core.timeout_pending(request_id).await {
                error!("timeout handling failed: {err:#}");
            }
        });

        Ok(())
    }

    async fn log_event(
        &self,
        request: &PermissionRequest,
        action: Action,
        rule_id: Option<i64>,
        reason: String,
    ) -> anyhow::Result<()> {
        let entry = EventLogEntry {
            id: 0,
            timestamp: now_ts(),
            pid: request.pid,
            executable: request.executable.clone(),
            target_path: request.target_path.clone(),
            permission: request.permission,
            action,
            rule_id,
            reason,
        };
        let _ = self.db.add_event(&entry)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct FileSnitchDbus {
    core: Arc<DaemonCore>,
}

#[interface(name = "org.filesnitch.Daemon")]
impl FileSnitchDbus {
    async fn status(&self) -> zbus::fdo::Result<DaemonStatus> {
        self.core.status().await.map_err(map_err)
    }

    async fn list_rules(&self) -> zbus::fdo::Result<Vec<Rule>> {
        self.core.list_rules().await.map_err(map_err)
    }

    async fn add_rule(&self, rule: NewRule) -> zbus::fdo::Result<Rule> {
        self.core.add_rule(rule).await.map_err(map_err)
    }

    async fn update_rule(&self, rule: Rule) -> zbus::fdo::Result<bool> {
        self.core.update_rule(&rule).await.map_err(map_err)?;
        Ok(true)
    }

    async fn delete_rule(&self, id: i64) -> zbus::fdo::Result<bool> {
        self.core.delete_rule(id).await.map_err(map_err)?;
        Ok(true)
    }

    async fn toggle_rule(&self, id: i64, enabled: bool) -> zbus::fdo::Result<bool> {
        self.core.toggle_rule(id, enabled).await.map_err(map_err)?;
        Ok(true)
    }

    async fn list_events(&self, limit: u32) -> zbus::fdo::Result<Vec<EventLogEntry>> {
        self.core.list_events(limit).await.map_err(map_err)
    }

    async fn get_config(&self) -> zbus::fdo::Result<DaemonConfig> {
        Ok(self.core.get_config().await)
    }

    async fn set_config(&self, config: DaemonConfig, #[zbus(signal_context)] ctxt: SignalContext<'_>) -> zbus::fdo::Result<bool> {
        self.core.set_config(config.clone()).await.map_err(map_err)?;
        Self::config_changed(&ctxt, config)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(true)
    }

    async fn submit_decision(&self, decision: DecisionInput) -> zbus::fdo::Result<bool> {
        self.core.submit_decision(decision).await.map_err(map_err)
    }

    async fn export_rules(&self) -> zbus::fdo::Result<String> {
        self.core.export_rules().await.map_err(map_err)
    }

    async fn import_rules(&self, data: String) -> zbus::fdo::Result<u32> {
        self.core.import_rules(&data).await.map_err(map_err)
    }

    #[zbus(signal)]
    async fn permission_request(ctxt: &SignalContext<'_>, request: PermissionRequest) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn event_logged(ctxt: &SignalContext<'_>, event: EventLogEntry) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn config_changed(ctxt: &SignalContext<'_>, config: DaemonConfig) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn rule_changed(ctxt: &SignalContext<'_>, rule: Rule) -> zbus::Result<()>;
}

pub async fn run_daemon(opts: DaemonOpts) -> anyhow::Result<()> {
    let config = load_config(opts.config_path.as_deref())?;
    let db = Arc::new(Database::open(&opts.db_path)?);
    let fanotify = Arc::new(FanotifyMonitor::new(&opts.home_mount_path)?);

    let core = Arc::new(DaemonCore {
        db,
        config_path: opts.config_path.clone(),
        config: RwLock::new(config),
        fanotify: fanotify.clone(),
        pending: Mutex::new(HashMap::new()),
        home_mount_path: opts.home_mount_path.clone(),
    });

    let iface = FileSnitchDbus { core: core.clone() };
    let connection = loop {
        let bind = async {
            ConnectionBuilder::system()?
                .name(DBUS_BUS_NAME)?
                .serve_at(DBUS_OBJECT_PATH, iface.clone())?
                .build()
                .await
        }
        .await;

        match bind {
            Ok(conn) => break conn,
            Err(err) if is_dbus_access_denied(&err) => {
                error!(
                    "D-Bus policy denied owning {DBUS_BUS_NAME}; retrying in 30s. error: {err}"
                );
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
            Err(err) => return Err(err).context("failed to bind system D-Bus service"),
        }
    };

    let (tx, mut rx) = mpsc::channel::<KernelEvent>(1024);
    spawn_fanotify_reader(fanotify, tx);

    info!("filesnitchd started and monitoring {}", opts.home_mount_path.display());

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                if let Some(event) = maybe_event {
                    if let Err(err) = core.handle_kernel_event(&connection, event).await {
                        warn!("kernel event handling failed: {err:#}");
                    }
                } else {
                    return Err(anyhow!("fanotify reader channel closed"));
                }
            }
            sig = tokio::signal::ctrl_c() => {
                sig.context("failed waiting for ctrl-c")?;
                info!("received ctrl-c, shutting down");
                break;
            }
        }
    }

    Ok(())
}

fn spawn_fanotify_reader(fanotify: Arc<FanotifyMonitor>, tx: mpsc::Sender<KernelEvent>) {
    tokio::task::spawn_blocking(move || {
        loop {
            match fanotify.read_events() {
                Ok(events) => {
                    for ev in events {
                        if tx.blocking_send(ev).is_err() {
                            return;
                        }
                    }
                }
                Err(err) => {
                    error!("fanotify read failed: {err:#}");
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }
        }
    });
}

fn map_err(err: anyhow::Error) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(err.to_string())
}

fn next_request_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    format!("req-{}-{}", now_ts(), SEQ.fetch_add(1, Ordering::Relaxed))
}

fn read_executable_for_pid(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| format!("/proc/{pid}/exe"))
}

fn read_uid_for_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid_line = status.lines().find(|line| line.starts_with("Uid:"))?;
    let mut parts = uid_line.split_whitespace();
    let _label = parts.next()?;
    parts.next()?.parse::<u32>().ok()
}

fn home_dir_for_uid(uid: u32, home_mount_path: &Path) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 7 {
            continue;
        }
        if let Ok(entry_uid) = fields[2].parse::<u32>() {
            if entry_uid == uid {
                return Some(PathBuf::from(fields[5]));
            }
        }
    }
    Some(home_mount_path.join(uid.to_string()))
}

fn has_interactive_frontend() -> bool {
    // UI process.
    if process_basename_exists("filesnitch-ui") {
        return true;
    }

    // CLI interactive watcher.
    process_cmdline_matches(|cmdline| {
        cmdline.iter().any(|arg| arg.ends_with("filesnitch"))
            && cmdline.iter().any(|arg| arg == "watch")
    })
}

fn process_basename_exists(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if !file_name
            .to_string_lossy()
            .chars()
            .all(|c| c.is_ascii_digit())
        {
            continue;
        }

        let exe_link = entry.path().join("exe");
        let Ok(exe_path) = std::fs::read_link(exe_link) else {
            continue;
        };
        if exe_path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|base| base == name)
        {
            return true;
        }
    }
    false
}

fn process_cmdline_matches(pred: impl Fn(&[String]) -> bool) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if !file_name
            .to_string_lossy()
            .chars()
            .all(|c| c.is_ascii_digit())
        {
            continue;
        }
        let cmdline_path = entry.path().join("cmdline");
        let Ok(raw) = std::fs::read(cmdline_path) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let args = raw
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).to_string())
            .collect::<Vec<_>>();
        if pred(&args) {
            return true;
        }
    }
    false
}

fn should_bypass_for_desktop_stability(executable: &str) -> bool {
    let base = Path::new(executable)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    matches!(
        base,
        // FileSnitch components must never self-intercept.
        "filesnitchd"
            | "filesnitch-ui"
            | "filesnitch"
            // Desktop/session core processes.
            | "gnome-shell"
            | "gnome-session-binary"
            | "dbus-daemon"
            | "Xwayland"
            | "Xorg"
            | "systemd"
            | "systemd-user-runtime-dir"
            | "wireplumber"
            | "pipewire"
            | "pipewire-pulse"
            | "pulseaudio"
            | "ibus-daemon"
            | "kded6"
            | "kwin_wayland"
            | "plasmashell"
    )
}

fn is_dbus_access_denied(err: &zbus::Error) -> bool {
    // zbus error nesting differs by backend/version, so keep matching robust.
    err.to_string()
        .contains("org.freedesktop.DBus.Error.AccessDenied")
}

fn rule_path_from_decision(request: &PermissionRequest, decision: &DecisionInput, home_dir: &Path) -> String {
    match decision.scope {
        RuleScope::ExactFile => request.target_path.clone(),
        RuleScope::Folder | RuleScope::FolderRecursive => Path::new(&request.target_path)
            .parent()
            .unwrap_or_else(|| Path::new(&request.target_path))
            .to_string_lossy()
            .to_string(),
        RuleScope::Home => home_dir.to_string_lossy().to_string(),
        RuleScope::Custom => decision
            .custom_path
            .clone()
            .unwrap_or_else(|| request.target_path.clone()),
    }
}
