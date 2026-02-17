use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A file-access rule persisted in the SQLite database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: i64,
    pub executable: PathBuf,
    pub path_pattern: String,
    pub permission: Permission,
    pub action: Action,
    pub is_critical: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub hit_count: u64,
    pub last_hit_at: Option<DateTime<Utc>>,
}

/// The kind of file access a rule governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    Write,
    ReadWrite,
}

/// Whether the rule allows or denies the access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

/// The access type observed at runtime (from fanotify).
#[derive(Debug, Clone, Copy)]
pub enum AccessType {
    Read,
    Write,
}

// ---------------------------------------------------------------------------
// Display impls (used when storing to SQLite as TEXT)
// ---------------------------------------------------------------------------

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Read => write!(f, "read"),
            Permission::Write => write!(f, "write"),
            Permission::ReadWrite => write!(f, "read_write"),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Allow => write!(f, "allow"),
            Action::Deny => write!(f, "deny"),
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_permission(s: &str) -> Result<Permission> {
    match s {
        "read" => Ok(Permission::Read),
        "write" => Ok(Permission::Write),
        "read_write" => Ok(Permission::ReadWrite),
        other => anyhow::bail!("unknown permission: {other}"),
    }
}

fn parse_action(s: &str) -> Result<Action> {
    match s {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        other => anyhow::bail!("unknown action: {other}"),
    }
}

/// Check whether a `Permission` covers the given `AccessType`.
///
/// `ReadWrite` matches both `Read` and `Write` access.
fn permission_matches(permission: Permission, access: AccessType) -> bool {
    match (permission, access) {
        (Permission::Read, AccessType::Read) => true,
        (Permission::Write, AccessType::Write) => true,
        (Permission::ReadWrite, _) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Path-pattern matching & specificity
// ---------------------------------------------------------------------------

/// Specificity levels used for rule priority ordering.
///   exact  = 4  (pattern is a literal path)
///   folder = 3  (pattern ends with /*)
///   recursive = 2  (pattern ends with /**)
///   home   = 1  (pattern is /home/<user>/**)
const SPECIFICITY_EXACT: u8 = 4;
const SPECIFICITY_FOLDER: u8 = 3;
const SPECIFICITY_RECURSIVE: u8 = 2;
const SPECIFICITY_HOME: u8 = 1;

/// Determine the specificity of a path pattern.
fn pattern_specificity(pattern: &str) -> u8 {
    if pattern.ends_with("/**") {
        // Check if it looks like a home-wide pattern: /home/<user>/**
        let prefix = &pattern[..pattern.len() - 3];
        let parts: Vec<&str> = prefix.split('/').collect();
        // /home/<user> splits into ["", "home", "<user>"]
        if parts.len() == 3 && parts[0].is_empty() && parts[1] == "home" && !parts[2].is_empty() {
            return SPECIFICITY_HOME;
        }
        SPECIFICITY_RECURSIVE
    } else if pattern.ends_with("/*") {
        SPECIFICITY_FOLDER
    } else {
        SPECIFICITY_EXACT
    }
}

/// Check if `target` matches the given `pattern`.
fn path_matches(pattern: &str, target: &Path) -> bool {
    let target_str = target.to_string_lossy();

    if pattern.ends_with("/**") {
        // Recursive glob: target must be anywhere under the directory.
        let dir = &pattern[..pattern.len() - 3];
        target_str.starts_with(dir) && target_str.len() > dir.len() && target_str.as_bytes()[dir.len()] == b'/'
    } else if pattern.ends_with("/*") {
        // Single-level glob: target must be a direct child.
        let dir = &pattern[..pattern.len() - 2];
        if let Some(parent) = target.parent() {
            parent.to_string_lossy() == dir
        } else {
            false
        }
    } else {
        // Exact match.
        target_str == pattern
    }
}

// ---------------------------------------------------------------------------
// Row → Rule
// ---------------------------------------------------------------------------

fn row_to_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<Rule> {
    let perm_str: String = row.get(3)?;
    let action_str: String = row.get(4)?;

    let permission = parse_permission(&perm_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let action = parse_action(&action_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let created_str: String = row.get(6)?;
    let expires_str: Option<String> = row.get(7)?;
    let last_hit_str: Option<String> = row.get(10)?;

    let created_at = DateTime::parse_from_rfc3339(&created_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?;

    let expires_at = expires_str
        .map(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
        })
        .transpose()?;

    let last_hit_at = last_hit_str
        .map(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        10,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
        })
        .transpose()?;

    Ok(Rule {
        id: row.get(0)?,
        executable: PathBuf::from(row.get::<_, String>(1)?),
        path_pattern: row.get(2)?,
        permission,
        action,
        is_critical: row.get::<_, i64>(5)? != 0,
        created_at,
        expires_at,
        enabled: row.get::<_, i64>(8)? != 0,
        hit_count: row.get::<_, i64>(9)? as u64,
        last_hit_at,
    })
}

// ---------------------------------------------------------------------------
// RuleStore
// ---------------------------------------------------------------------------

/// Persistent rule store backed by SQLite with an in-memory cache for fast
/// lookups in the fanotify event loop.
pub struct RuleStore {
    /// SQLite connection (serialised by a Mutex).
    db: Mutex<Connection>,
    /// In-memory cache keyed by executable path string.
    cache: Mutex<HashMap<String, Vec<Rule>>>,
}

impl RuleStore {
    /// Open (or create) the SQLite database at `db_path`, run migrations,
    /// and load all existing rules into the in-memory cache.
    pub fn new(db_path: &Path) -> Result<Self> {
        // Ensure parent directory exists.
        if let Some(parent) = db_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create db directory: {}", parent.display()))?;
            }
        }

        let conn =
            Connection::open(db_path).with_context(|| format!("failed to open db: {}", db_path.display()))?;

        // Enable WAL mode for concurrent access.
        conn.pragma_update(None, "journal_mode", "WAL")?;

        // Create the rules table and indices.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS rules (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                executable    TEXT    NOT NULL,
                path_pattern  TEXT    NOT NULL,
                permission    TEXT    NOT NULL,
                action        TEXT    NOT NULL,
                is_critical   INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT    NOT NULL,
                expires_at    TEXT,
                enabled       INTEGER NOT NULL DEFAULT 1,
                hit_count     INTEGER NOT NULL DEFAULT 0,
                last_hit_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_rules_executable ON rules(executable);
            CREATE INDEX IF NOT EXISTS idx_rules_expires    ON rules(expires_at);",
        )?;

        // Load all rules into the cache.
        let cache = Self::load_all_rules(&conn)?;

        Ok(Self {
            db: Mutex::new(conn),
            cache: Mutex::new(cache),
        })
    }

    /// Load every rule from the database grouped by executable path.
    fn load_all_rules(conn: &Connection) -> Result<HashMap<String, Vec<Rule>>> {
        let mut stmt = conn.prepare(
            "SELECT id, executable, path_pattern, permission, action,
                    is_critical, created_at, expires_at, enabled,
                    hit_count, last_hit_at
             FROM rules",
        )?;

        let rules_iter = stmt.query_map([], |row| row_to_rule(row))?;

        let mut map: HashMap<String, Vec<Rule>> = HashMap::new();
        for rule_result in rules_iter {
            let rule = rule_result?;
            let key = rule.executable.to_string_lossy().to_string();
            map.entry(key).or_default().push(rule);
        }
        Ok(map)
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    /// Find the highest-priority matching rule for the given access event.
    ///
    /// Only enabled, non-expired rules are considered.  Rules are sorted by:
    ///   1. `is_critical` descending (critical rules first)
    ///   2. path specificity descending (exact > folder > recursive > home)
    ///   3. action (Deny beats Allow at equal specificity)
    ///
    /// The first rule after sorting is returned.
    pub fn find_matching_rule(
        &self,
        executable: &Path,
        target_path: &Path,
        access_type: AccessType,
    ) -> Option<Rule> {
        let cache = self.cache.lock().expect("rule cache lock poisoned");
        let key = executable.to_string_lossy().to_string();

        let rules = cache.get(&key)?;
        let now = Utc::now();

        // Collect all matching candidates with their specificity.
        let mut candidates: Vec<(u8, &Rule)> = rules
            .iter()
            .filter(|r| {
                // Must be enabled.
                if !r.enabled {
                    return false;
                }
                // Must not be expired.
                if let Some(exp) = r.expires_at {
                    if exp <= now {
                        return false;
                    }
                }
                // Permission must cover the access type.
                if !permission_matches(r.permission, access_type) {
                    return false;
                }
                // Path pattern must match the target.
                path_matches(&r.path_pattern, target_path)
            })
            .map(|r| (pattern_specificity(&r.path_pattern), r))
            .collect();

        // Sort: critical desc, specificity desc, deny before allow.
        candidates.sort_by(|a, b| {
            let crit_cmp = b.1.is_critical.cmp(&a.1.is_critical);
            if crit_cmp != std::cmp::Ordering::Equal {
                return crit_cmp;
            }
            let spec_cmp = b.0.cmp(&a.0);
            if spec_cmp != std::cmp::Ordering::Equal {
                return spec_cmp;
            }
            // Deny (1) > Allow (0)
            let action_ord = |act: Action| -> u8 {
                match act {
                    Action::Deny => 1,
                    Action::Allow => 0,
                }
            };
            action_ord(b.1.action).cmp(&action_ord(a.1.action))
        });

        candidates.first().map(|(_, r)| (*r).clone())
    }

    // -----------------------------------------------------------------------
    // Mutation
    // -----------------------------------------------------------------------

    /// Insert a new rule into the database and update the in-memory cache.
    ///
    /// Returns the auto-generated row id.
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule(
        &self,
        executable: PathBuf,
        path_pattern: String,
        permission: Permission,
        action: Action,
        is_critical: bool,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<i64> {
        let now = Utc::now();
        let created_str = now.to_rfc3339();
        let expires_str = expires_at.map(|dt| dt.to_rfc3339());
        let exe_str = executable.to_string_lossy().to_string();

        let db = self.db.lock().expect("db lock poisoned");
        db.execute(
            "INSERT INTO rules (executable, path_pattern, permission, action, is_critical, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                exe_str,
                path_pattern,
                permission.to_string(),
                action.to_string(),
                is_critical as i64,
                created_str,
                expires_str,
            ],
        )?;

        let id = db.last_insert_rowid();

        let rule = Rule {
            id,
            executable: executable.clone(),
            path_pattern,
            permission,
            action,
            is_critical,
            created_at: now,
            expires_at,
            enabled: true,
            hit_count: 0,
            last_hit_at: None,
        };

        let mut cache = self.cache.lock().expect("rule cache lock poisoned");
        cache.entry(exe_str).or_default().push(rule);

        Ok(id)
    }

    /// Delete a rule by its id from both the database and the cache.
    pub fn delete_rule(&self, id: i64) -> Result<()> {
        let db = self.db.lock().expect("db lock poisoned");
        let affected = db.execute("DELETE FROM rules WHERE id = ?1", params![id])?;
        if affected == 0 {
            anyhow::bail!("rule with id {id} not found");
        }
        drop(db);

        let mut cache = self.cache.lock().expect("rule cache lock poisoned");
        for rules in cache.values_mut() {
            rules.retain(|r| r.id != id);
        }
        // Remove empty entries to keep the map tidy.
        cache.retain(|_, v| !v.is_empty());

        Ok(())
    }

    /// List all rules, optionally filtered by executable path substring.
    pub fn list_rules(&self, app_filter: Option<&str>) -> Result<Vec<Rule>> {
        let cache = self.cache.lock().expect("rule cache lock poisoned");
        let mut result = Vec::new();

        for (key, rules) in cache.iter() {
            if let Some(filter) = app_filter {
                if !key.contains(filter) {
                    continue;
                }
            }
            result.extend(rules.iter().cloned());
        }

        // Return in deterministic order (by id).
        result.sort_by_key(|r| r.id);
        Ok(result)
    }

    /// Record a cache/db hit: increment `hit_count` and set `last_hit_at`.
    pub fn record_hit(&self, id: i64) -> Result<()> {
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        let db = self.db.lock().expect("db lock poisoned");
        db.execute(
            "UPDATE rules SET hit_count = hit_count + 1, last_hit_at = ?1 WHERE id = ?2",
            params![now_str, id],
        )?;
        drop(db);

        let mut cache = self.cache.lock().expect("rule cache lock poisoned");
        for rules in cache.values_mut() {
            if let Some(rule) = rules.iter_mut().find(|r| r.id == id) {
                rule.hit_count += 1;
                rule.last_hit_at = Some(now);
                break;
            }
        }

        Ok(())
    }

    /// Remove expired rules from both the database and the cache.
    pub fn cleanup_expired(&self) -> Result<()> {
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        let db = self.db.lock().expect("db lock poisoned");
        db.execute(
            "DELETE FROM rules WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now_str],
        )?;
        drop(db);

        let mut cache = self.cache.lock().expect("rule cache lock poisoned");
        for rules in cache.values_mut() {
            rules.retain(|r| {
                if let Some(exp) = r.expires_at {
                    exp > now
                } else {
                    true
                }
            });
        }
        cache.retain(|_, v| !v.is_empty());

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Import / Export
    // -----------------------------------------------------------------------

    /// Serialize all rules as a JSON string.
    pub fn export_json(&self) -> Result<String> {
        let rules = self.list_rules(None)?;
        let json = serde_json::to_string_pretty(&rules)
            .context("failed to serialize rules to JSON")?;
        Ok(json)
    }

    /// Deserialize rules from a JSON string and insert them into the store.
    ///
    /// Existing `id`, `hit_count`, `last_hit_at`, and `created_at` fields in
    /// the JSON are ignored; each imported rule gets a fresh row id and
    /// creation timestamp.
    ///
    /// Returns the number of rules imported.
    pub fn import_json(&self, json: &str) -> Result<u32> {
        let rules: Vec<Rule> =
            serde_json::from_str(json).context("failed to deserialize rules from JSON")?;

        let mut count: u32 = 0;
        for rule in rules {
            self.add_rule(
                rule.executable,
                rule.path_pattern,
                rule.permission,
                rule.action,
                rule.is_critical,
                rule.expires_at,
            )?;
            count += 1;
        }
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Create a RuleStore backed by an in-memory SQLite database.
    fn temp_store() -> RuleStore {
        // Use a temporary file so `new` can run its full init logic.
        let dir = std::env::temp_dir().join(format!("filesnitch-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test_rules.db");
        // Remove leftover database from a previous run.
        let _ = std::fs::remove_file(&db_path);
        RuleStore::new(&db_path).expect("failed to create test store")
    }

    #[test]
    fn add_and_list_rules() {
        let store = temp_store();
        let id = store
            .add_rule(
                PathBuf::from("/usr/bin/curl"),
                "/home/user/.ssh/**".into(),
                Permission::Read,
                Action::Deny,
                true,
                None,
            )
            .unwrap();
        assert!(id > 0);

        let rules = store.list_rules(None).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, id);
        assert_eq!(rules[0].action, Action::Deny);
    }

    #[test]
    fn delete_rule() {
        let store = temp_store();
        let id = store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/secret".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        store.delete_rule(id).unwrap();
        let rules = store.list_rules(None).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn delete_nonexistent_rule_errors() {
        let store = temp_store();
        assert!(store.delete_rule(9999).is_err());
    }

    #[test]
    fn find_exact_match() {
        let store = temp_store();
        store
            .add_rule(
                PathBuf::from("/usr/bin/vim"),
                "/home/user/.bashrc".into(),
                Permission::ReadWrite,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        let found = store
            .find_matching_rule(
                Path::new("/usr/bin/vim"),
                Path::new("/home/user/.bashrc"),
                AccessType::Write,
            )
            .expect("should find a match");
        assert_eq!(found.action, Action::Allow);
    }

    #[test]
    fn find_folder_glob() {
        let store = temp_store();
        store
            .add_rule(
                PathBuf::from("/usr/bin/ls"),
                "/home/user/.ssh/*".into(),
                Permission::Read,
                Action::Deny,
                false,
                None,
            )
            .unwrap();

        // Direct child should match.
        let found = store.find_matching_rule(
            Path::new("/usr/bin/ls"),
            Path::new("/home/user/.ssh/id_rsa"),
            AccessType::Read,
        );
        assert!(found.is_some());

        // Nested path should NOT match single-level glob.
        let found = store.find_matching_rule(
            Path::new("/usr/bin/ls"),
            Path::new("/home/user/.ssh/subdir/key"),
            AccessType::Read,
        );
        assert!(found.is_none());
    }

    #[test]
    fn find_recursive_glob() {
        let store = temp_store();
        store
            .add_rule(
                PathBuf::from("/usr/bin/find"),
                "/home/user/.config/**".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        let found = store.find_matching_rule(
            Path::new("/usr/bin/find"),
            Path::new("/home/user/.config/deep/nested/file"),
            AccessType::Read,
        );
        assert!(found.is_some());
    }

    #[test]
    fn critical_rule_takes_priority() {
        let store = temp_store();

        // Non-critical allow.
        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/home/user/.ssh/**".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        // Critical deny (same pattern).
        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/home/user/.ssh/**".into(),
                Permission::Read,
                Action::Deny,
                true,
                None,
            )
            .unwrap();

        let found = store
            .find_matching_rule(
                Path::new("/usr/bin/cat"),
                Path::new("/home/user/.ssh/id_rsa"),
                AccessType::Read,
            )
            .expect("should match");
        assert_eq!(found.action, Action::Deny);
        assert!(found.is_critical);
    }

    #[test]
    fn deny_beats_allow_at_same_specificity() {
        let store = temp_store();

        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/data".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/data".into(),
                Permission::Read,
                Action::Deny,
                false,
                None,
            )
            .unwrap();

        let found = store
            .find_matching_rule(
                Path::new("/usr/bin/cat"),
                Path::new("/tmp/data"),
                AccessType::Read,
            )
            .expect("should match");
        assert_eq!(found.action, Action::Deny);
    }

    #[test]
    fn exact_beats_glob() {
        let store = temp_store();

        // Glob deny.
        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/home/user/.ssh/*".into(),
                Permission::Read,
                Action::Deny,
                false,
                None,
            )
            .unwrap();

        // Exact allow.
        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/home/user/.ssh/authorized_keys".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        let found = store
            .find_matching_rule(
                Path::new("/usr/bin/cat"),
                Path::new("/home/user/.ssh/authorized_keys"),
                AccessType::Read,
            )
            .expect("should match");
        assert_eq!(found.action, Action::Allow);
    }

    #[test]
    fn expired_rule_is_skipped() {
        let store = temp_store();
        let past = Utc::now() - chrono::Duration::hours(1);
        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/secret".into(),
                Permission::Read,
                Action::Allow,
                false,
                Some(past),
            )
            .unwrap();

        let found = store.find_matching_rule(
            Path::new("/usr/bin/cat"),
            Path::new("/tmp/secret"),
            AccessType::Read,
        );
        assert!(found.is_none());
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let store = temp_store();
        let id = store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/secret".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        // Manually disable the rule in the cache.
        {
            let mut cache = store.cache.lock().unwrap();
            for rules in cache.values_mut() {
                for r in rules.iter_mut() {
                    if r.id == id {
                        r.enabled = false;
                    }
                }
            }
        }

        let found = store.find_matching_rule(
            Path::new("/usr/bin/cat"),
            Path::new("/tmp/secret"),
            AccessType::Read,
        );
        assert!(found.is_none());
    }

    #[test]
    fn permission_compatibility() {
        let store = temp_store();
        store
            .add_rule(
                PathBuf::from("/usr/bin/vim"),
                "/tmp/file".into(),
                Permission::ReadWrite,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        // ReadWrite should match a Read access.
        assert!(store
            .find_matching_rule(
                Path::new("/usr/bin/vim"),
                Path::new("/tmp/file"),
                AccessType::Read,
            )
            .is_some());

        // ReadWrite should match a Write access.
        assert!(store
            .find_matching_rule(
                Path::new("/usr/bin/vim"),
                Path::new("/tmp/file"),
                AccessType::Write,
            )
            .is_some());
    }

    #[test]
    fn permission_mismatch() {
        let store = temp_store();
        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/file".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        // Read-only rule should NOT match a Write access.
        assert!(store
            .find_matching_rule(
                Path::new("/usr/bin/cat"),
                Path::new("/tmp/file"),
                AccessType::Write,
            )
            .is_none());
    }

    #[test]
    fn record_hit_increments() {
        let store = temp_store();
        let id = store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/file".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        store.record_hit(id).unwrap();
        store.record_hit(id).unwrap();

        let rules = store.list_rules(None).unwrap();
        assert_eq!(rules[0].hit_count, 2);
        assert!(rules[0].last_hit_at.is_some());
    }

    #[test]
    fn cleanup_expired_removes_old_rules() {
        let store = temp_store();
        let past = Utc::now() - chrono::Duration::hours(1);
        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/old".into(),
                Permission::Read,
                Action::Allow,
                false,
                Some(past),
            )
            .unwrap();
        store
            .add_rule(
                PathBuf::from("/usr/bin/cat"),
                "/tmp/current".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        store.cleanup_expired().unwrap();

        let rules = store.list_rules(None).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].path_pattern, "/tmp/current");
    }

    #[test]
    fn export_and_import_json() {
        let store = temp_store();
        store
            .add_rule(
                PathBuf::from("/usr/bin/curl"),
                "/home/user/.ssh/**".into(),
                Permission::Read,
                Action::Deny,
                true,
                None,
            )
            .unwrap();
        store
            .add_rule(
                PathBuf::from("/usr/bin/wget"),
                "/tmp/*".into(),
                Permission::Write,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        let json = store.export_json().unwrap();

        // Import into a fresh store.
        let store2 = temp_store();
        let count = store2.import_json(&json).unwrap();
        assert_eq!(count, 2);

        let rules = store2.list_rules(None).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn list_rules_with_filter() {
        let store = temp_store();
        store
            .add_rule(
                PathBuf::from("/usr/bin/curl"),
                "/tmp/*".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();
        store
            .add_rule(
                PathBuf::from("/usr/bin/wget"),
                "/tmp/*".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        let filtered = store.list_rules(Some("curl")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered[0].executable,
            PathBuf::from("/usr/bin/curl")
        );
    }

    #[test]
    fn home_wide_specificity() {
        assert_eq!(pattern_specificity("/home/user/**"), SPECIFICITY_HOME);
        assert_eq!(pattern_specificity("/home/user/.config/**"), SPECIFICITY_RECURSIVE);
        assert_eq!(pattern_specificity("/home/user/.ssh/*"), SPECIFICITY_FOLDER);
        assert_eq!(pattern_specificity("/home/user/.bashrc"), SPECIFICITY_EXACT);
    }

    #[test]
    fn no_match_for_different_executable() {
        let store = temp_store();
        store
            .add_rule(
                PathBuf::from("/usr/bin/curl"),
                "/tmp/file".into(),
                Permission::Read,
                Action::Allow,
                false,
                None,
            )
            .unwrap();

        let found = store.find_matching_rule(
            Path::new("/usr/bin/wget"),
            Path::new("/tmp/file"),
            AccessType::Read,
        );
        assert!(found.is_none());
    }
}
