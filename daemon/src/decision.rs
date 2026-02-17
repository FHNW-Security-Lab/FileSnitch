use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::config::{Config, DefaultAction, OperationMode, ProtectionMode};
use crate::exclusions::ExclusionList;
use crate::fanotify::{AccessType, FanotifyEvent};
use crate::process_info::ProcessInfoCache;
use crate::rules::{Action, Permission, RuleStore};

/// Counter for generating unique request IDs for pending prompts.
static NEXT_PENDING_ID: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A request waiting for user input via D-Bus / UI.
///
/// Created when no rule matches an access event and the daemon needs the
/// user to decide whether to allow or deny the access. The UI picks these
/// up via D-Bus, presents a prompt, and sends the decision back through
/// `response_tx`.
pub struct PendingRequest {
    pub request_id: u64,
    pub pid: i32,
    pub executable: String,
    pub target_path: String,
    pub access_type: String,
    pub app_name: String,
    pub timestamp: u64,
    pub response_tx: oneshot::Sender<UserDecision>,
}

/// The user's response to a pending access-permission prompt.
#[derive(Debug, Clone)]
pub struct UserDecision {
    /// Whether to allow or deny the access.
    pub action: Action,
    /// How long the rule should last: "once", "1m", "10m", "60m", "12h", "forever".
    pub duration: String,
    /// Scope of the path pattern: "exact", "folder", "recursive", "home", or a custom path.
    pub path_scope: String,
    /// Permission type: "read", "write", "readwrite".
    pub permission: String,
}

// ---------------------------------------------------------------------------
// DecisionEngine
// ---------------------------------------------------------------------------

/// Notification payload sent when a new pending request is created.
///
/// Contains the fields needed to emit a D-Bus `PermissionRequest` signal:
/// `(request_id, pid, executable, target_path, access_type, app_name, timestamp)`.
pub type PendingNotification = (u64, i32, String, String, String, String, u64);

/// The core decision engine that sits between fanotify events and D-Bus.
///
/// For each incoming fanotify permission event the engine:
/// 1. Resolves process information.
/// 2. Checks exclusions (system processes, built-in lists).
/// 3. Filters events outside `/home` or non-critical paths.
/// 4. Looks up existing rules.
/// 5. If no rule matches, creates a pending prompt for the user/UI.
/// 6. Applies a timeout-based default when the user does not respond.
pub struct DecisionEngine {
    pub config: Arc<RwLock<Config>>,
    pub rules: Arc<RuleStore>,
    pub exclusions: Arc<RwLock<ExclusionList>>,
    pub process_cache: Arc<ProcessInfoCache>,
    pub pending_requests: Arc<RwLock<HashMap<u64, PendingRequest>>>,
    pub pending_notify_tx: mpsc::UnboundedSender<PendingNotification>,
}

impl DecisionEngine {
    /// Create a new decision engine with all shared state.
    pub fn new(
        config: Arc<RwLock<Config>>,
        rules: Arc<RuleStore>,
        exclusions: Arc<RwLock<ExclusionList>>,
        process_cache: Arc<ProcessInfoCache>,
        pending_requests: Arc<RwLock<HashMap<u64, PendingRequest>>>,
        pending_notify_tx: mpsc::UnboundedSender<PendingNotification>,
    ) -> Self {
        Self {
            config,
            rules,
            exclusions,
            process_cache,
            pending_requests,
            pending_notify_tx,
        }
    }

    /// Make an access decision for the given fanotify event.
    ///
    /// Returns `(allowed, reason)` where `allowed` indicates whether the
    /// access should be permitted, and `reason` is a short tag explaining
    /// why (for logging and audit).
    pub async fn decide(&self, event: &FanotifyEvent) -> (bool, String) {
        // 1. Resolve process info. If the process is gone, auto-allow.
        let process_info = match self.process_cache.resolve(event.pid) {
            Ok(info) => info,
            Err(_) => {
                tracing::debug!(
                    pid = event.pid,
                    path = %event.target_path.display(),
                    "process gone, auto-allowing"
                );
                return (true, "process_gone".to_string());
            }
        };

        // 2. Check the exclusion list.
        {
            let exclusions = self.exclusions.read().await;
            if exclusions.is_excluded(&process_info) {
                tracing::debug!(
                    pid = event.pid,
                    exe = %process_info.executable.display(),
                    "excluded process, auto-allowing"
                );
                return (true, "excluded".to_string());
            }
        }

        let target_str = event.target_path.to_string_lossy();

        // 3. If the target path is not under /home, auto-allow.
        if !target_str.starts_with("/home") {
            tracing::debug!(
                path = %target_str,
                "target not under /home, auto-allowing"
            );
            return (true, "not_home".to_string());
        }

        // Read config values we need for the remaining checks.
        let (operation_mode, protection_mode, default_action, prompt_timeout, critical_paths) = {
            let cfg = self.config.read().await;
            (
                cfg.general.operation_mode,
                cfg.general.protection_mode,
                cfg.general.default_action,
                cfg.general.prompt_timeout,
                cfg.critical_paths.paths.clone(),
            )
        };

        // 4. In learning mode, auto-allow everything.
        if operation_mode == OperationMode::Learning {
            tracing::debug!(
                pid = event.pid,
                path = %target_str,
                "learning mode, auto-allowing"
            );
            return (true, "learning".to_string());
        }

        // 5. In CriticalOnly mode, skip non-critical paths.
        if protection_mode == ProtectionMode::CriticalOnly
            && !self.is_critical_path(&event.target_path, &critical_paths)
        {
            tracing::debug!(
                path = %target_str,
                "not a critical path in critical-only mode, auto-allowing"
            );
            return (true, "not_critical".to_string());
        }

        // 6. Convert fanotify AccessType to rules::AccessType and look up rules.
        let rules_access = match event.access_type {
            AccessType::Read => crate::rules::AccessType::Read,
            AccessType::Write => crate::rules::AccessType::Write,
        };

        if let Some(rule) = self.rules.find_matching_rule(
            &process_info.executable,
            &event.target_path,
            rules_access,
        ) {
            // Record the hit (best-effort; ignore errors).
            if let Err(e) = self.rules.record_hit(rule.id) {
                tracing::warn!(rule_id = rule.id, error = %e, "failed to record rule hit");
            }
            let allowed = rule.action == Action::Allow;
            let reason = format!("rule:{}", rule.id);
            tracing::debug!(
                pid = event.pid,
                path = %target_str,
                rule_id = rule.id,
                action = %rule.action,
                "matched existing rule"
            );
            return (allowed, reason);
        }

        // 7. No matching rule -- create a pending request with a oneshot channel.
        let request_id = NEXT_PENDING_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel::<UserDecision>();

        let access_type_str = match event.access_type {
            AccessType::Read => "read",
            AccessType::Write => "write",
        };

        // Derive a human-friendly app name from the executable.
        let app_name = process_info
            .executable
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| process_info.comm.clone());

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pending = PendingRequest {
            request_id,
            pid: event.pid,
            executable: process_info.executable.to_string_lossy().to_string(),
            target_path: target_str.to_string(),
            access_type: access_type_str.to_string(),
            app_name: app_name.clone(),
            timestamp: now_ts,
            response_tx: tx,
        };

        {
            let mut pending_map = self.pending_requests.write().await;
            pending_map.insert(request_id, pending);
        }

        // Notify the main loop so it can emit a D-Bus PermissionRequest signal.
        let _ = self.pending_notify_tx.send((
            request_id,
            event.pid,
            process_info.executable.to_string_lossy().to_string(),
            target_str.to_string(),
            access_type_str.to_string(),
            app_name.clone(),
            now_ts,
        ));

        tracing::info!(
            request_id,
            pid = event.pid,
            app = %app_name,
            path = %target_str,
            access = access_type_str,
            timeout = prompt_timeout,
            "awaiting user decision"
        );

        // 8. Wait for user response with a timeout.
        let timeout_duration = Duration::from_secs(u64::from(prompt_timeout));
        let result = tokio::time::timeout(timeout_duration, rx).await;

        match result {
            // 9. User responded in time.
            Ok(Ok(decision)) => {
                // Remove from pending (may already be gone if responder cleaned up).
                {
                    let mut pending_map = self.pending_requests.write().await;
                    pending_map.remove(&request_id);
                }

                let allowed = decision.action == Action::Allow;

                tracing::info!(
                    request_id,
                    action = %decision.action,
                    duration = %decision.duration,
                    path_scope = %decision.path_scope,
                    "user responded"
                );

                // Create a persistent rule if the duration is not "once".
                if decision.duration != "once" {
                    if let Err(e) = self.create_rule_from_decision(
                        &process_info.executable.to_string_lossy(),
                        &target_str,
                        &decision,
                        &critical_paths,
                    ) {
                        tracing::error!(error = %e, "failed to create rule from user decision");
                    }
                }

                (allowed, "user".to_string())
            }
            // 10. Timeout or channel error -- apply default action.
            Ok(Err(_)) | Err(_) => {
                // Remove from pending.
                {
                    let mut pending_map = self.pending_requests.write().await;
                    pending_map.remove(&request_id);
                }

                let allowed = default_action == DefaultAction::Allow;
                tracing::info!(
                    request_id,
                    default_action = %default_action,
                    "prompt timed out or channel closed, applying default"
                );

                (allowed, "timeout".to_string())
            }
        }
    }

    /// Create a persistent rule from a user's decision.
    ///
    /// Computes the path pattern from the `path_scope`, the expiration from
    /// `duration`, and inserts the rule via `RuleStore::add_rule`.
    fn create_rule_from_decision(
        &self,
        executable: &str,
        target_path: &str,
        decision: &UserDecision,
        critical_paths: &[String],
    ) -> Result<()> {
        // Compute path pattern from scope.
        let path_pattern = match decision.path_scope.as_str() {
            "exact" => target_path.to_string(),
            "folder" => {
                let parent = Path::new(target_path)
                    .parent()
                    .unwrap_or_else(|| Path::new("/"));
                format!("{}/*", parent.display())
            }
            "recursive" => {
                let parent = Path::new(target_path)
                    .parent()
                    .unwrap_or_else(|| Path::new("/"));
                format!("{}/**", parent.display())
            }
            "home" => {
                // Extract /home/<username> from the target path.
                let home_dir =
                    extract_home_dir(target_path).unwrap_or_else(|| "/home/user".to_string());
                format!("{home_dir}/**")
            }
            custom => custom.to_string(),
        };

        // Compute expiration from duration.
        let expires_at = match decision.duration.as_str() {
            "once" => {
                // Should not reach here (caller guards), but handle gracefully.
                return Ok(());
            }
            "1m" => Some(Utc::now() + chrono::Duration::minutes(1)),
            "10m" => Some(Utc::now() + chrono::Duration::minutes(10)),
            "60m" => Some(Utc::now() + chrono::Duration::minutes(60)),
            "12h" => Some(Utc::now() + chrono::Duration::hours(12)),
            "forever" => None,
            other => {
                tracing::warn!(duration = other, "unknown duration, treating as forever");
                None
            }
        };

        // Parse permission string.
        let permission = match decision.permission.as_str() {
            "read" => Permission::Read,
            "write" => Permission::Write,
            "readwrite" | "read_write" => Permission::ReadWrite,
            other => {
                tracing::warn!(
                    permission = other,
                    "unknown permission, defaulting to ReadWrite"
                );
                Permission::ReadWrite
            }
        };

        // Determine whether the target is on a critical path.
        let is_critical = self.is_critical_path(Path::new(target_path), critical_paths);

        let id = self
            .rules
            .add_rule(
                std::path::PathBuf::from(executable),
                path_pattern.clone(),
                permission,
                decision.action,
                is_critical,
                expires_at,
            )
            .with_context(|| {
                format!(
                    "failed to add rule for {} -> {}",
                    executable, path_pattern
                )
            })?;

        tracing::info!(
            rule_id = id,
            executable,
            path_pattern,
            permission = %permission,
            action = %decision.action,
            is_critical,
            "created rule from user decision"
        );

        Ok(())
    }

    /// Check if a target path is considered critical.
    ///
    /// Strips the `/home/<username>/` prefix from the target and checks
    /// whether the remainder starts with any of the configured critical
    /// path patterns.
    pub fn is_critical_path(&self, target: &Path, critical_paths: &[String]) -> bool {
        let target_str = target.to_string_lossy();

        // Extract the portion after /home/<username>/
        let relative = match strip_home_prefix(&target_str) {
            Some(rel) => rel,
            None => return false,
        };

        for pattern in critical_paths {
            if relative == *pattern {
                return true;
            }
            if relative.starts_with(pattern.as_str()) {
                // Ensure it is a proper prefix (followed by '/' or is exact).
                let next_char = relative.as_bytes().get(pattern.len());
                if next_char == Some(&b'/') || next_char.is_none() {
                    return true;
                }
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the home directory portion from a path
/// (e.g., "/home/alice/..." -> "/home/alice").
fn extract_home_dir(path: &str) -> Option<String> {
    if !path.starts_with("/home/") {
        return None;
    }
    let rest = &path["/home/".len()..];
    let username = rest.split('/').next()?;
    if username.is_empty() {
        return None;
    }
    Some(format!("/home/{username}"))
}

/// Strip the `/home/<username>/` prefix from a path, returning the relative
/// portion after the home directory.
fn strip_home_prefix(path: &str) -> Option<&str> {
    if !path.starts_with("/home/") {
        return None;
    }
    let rest = &path["/home/".len()..];
    // Skip the username component.
    let slash_pos = rest.find('/')?;
    let relative = &rest[slash_pos + 1..];
    if relative.is_empty() {
        return None;
    }
    Some(relative)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_home_dir_valid() {
        assert_eq!(
            extract_home_dir("/home/alice/.ssh/id_rsa"),
            Some("/home/alice".to_string())
        );
        assert_eq!(
            extract_home_dir("/home/bob/Documents/file.txt"),
            Some("/home/bob".to_string())
        );
    }

    #[test]
    fn extract_home_dir_invalid() {
        assert_eq!(extract_home_dir("/tmp/file"), None);
        assert_eq!(extract_home_dir("/home/"), None);
    }

    #[test]
    fn strip_home_prefix_valid() {
        assert_eq!(
            strip_home_prefix("/home/alice/.ssh/id_rsa"),
            Some(".ssh/id_rsa")
        );
        assert_eq!(strip_home_prefix("/home/bob/.bashrc"), Some(".bashrc"));
    }

    #[test]
    fn strip_home_prefix_invalid() {
        assert_eq!(strip_home_prefix("/tmp/file"), None);
        assert_eq!(strip_home_prefix("/home/alice/"), None);
        assert_eq!(strip_home_prefix("/home/alice"), None);
    }

    #[test]
    fn test_is_critical_path() {
        let config = crate::config::Config::default();
        let exclusions = ExclusionList::new(&config);
        let process_cache = ProcessInfoCache::new();

        // Use a temp dir for the rule store DB.
        let dir = std::env::temp_dir().join(format!("filesnitch-decision-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test_decision.db");
        let _ = std::fs::remove_file(&db_path);
        let rules = RuleStore::new(&db_path).unwrap();

        let (notify_tx, _notify_rx) = mpsc::unbounded_channel();
        let engine = DecisionEngine::new(
            Arc::new(RwLock::new(config)),
            Arc::new(rules),
            Arc::new(RwLock::new(exclusions)),
            Arc::new(process_cache),
            Arc::new(RwLock::new(HashMap::new())),
            notify_tx,
        );

        let critical_paths = vec![
            ".ssh".to_string(),
            ".gnupg".to_string(),
            ".bashrc".to_string(),
            ".config/Code".to_string(),
        ];

        assert!(engine.is_critical_path(
            Path::new("/home/alice/.ssh/id_rsa"),
            &critical_paths
        ));
        assert!(engine.is_critical_path(
            Path::new("/home/alice/.bashrc"),
            &critical_paths
        ));
        assert!(engine.is_critical_path(
            Path::new("/home/bob/.config/Code/settings.json"),
            &critical_paths
        ));
        assert!(!engine.is_critical_path(
            Path::new("/home/alice/Documents/file.txt"),
            &critical_paths
        ));
        assert!(!engine.is_critical_path(Path::new("/tmp/file"), &critical_paths));
        // ".sshx" should not match ".ssh"
        assert!(!engine.is_critical_path(
            Path::new("/home/alice/.sshx/something"),
            &critical_paths
        ));
    }
}
