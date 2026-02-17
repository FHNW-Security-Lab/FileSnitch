use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

/// A single access-decision event recorded by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub pid: i32,
    pub executable: PathBuf,
    pub target_path: PathBuf,
    pub access_type: String,  // "read" or "write"
    pub decision: String,     // "allow" or "deny"
    pub reason: String,       // "rule", "user", "timeout", "excluded", "learning", "not_critical", "not_home"
    pub rule_id: Option<i64>,
}

/// Persistent event log backed by a SQLite database.
///
/// All access decisions (allow / deny) are recorded here so the GUI
/// event-log tab and the `filesnitch log` CLI command can display them.
/// The underlying database file is shared with `RuleStore`; both use
/// different tables in the same SQLite file.
pub struct EventLog {
    conn: Mutex<Connection>,
}

impl EventLog {
    /// Open (or create) the SQLite database at `db_path` and ensure the
    /// `events` table and its indexes exist.
    pub fn new(db_path: &Path) -> Result<Self> {
        // Ensure the parent directory exists so SQLite can create the file.
        if let Some(parent) = db_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create database directory: {}",
                        parent.display()
                    )
                })?;
            }
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("failed to open event log database: {}", db_path.display()))?;

        // Enable WAL mode for better concurrent read/write performance.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                pid INTEGER NOT NULL,
                executable TEXT NOT NULL,
                target_path TEXT NOT NULL,
                access_type TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                rule_id INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_executable ON events(executable);",
        )
        .context("failed to create events table")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Record an access-decision event and return the new row id.
    pub fn log_event(
        &self,
        pid: i32,
        executable: &Path,
        target_path: &Path,
        access_type: &str,
        decision: &str,
        reason: &str,
        rule_id: Option<i64>,
    ) -> Result<i64> {
        let timestamp = Utc::now().to_rfc3339();
        let executable_str = executable.to_string_lossy();
        let target_path_str = target_path.to_string_lossy();

        let conn = self.conn.lock().expect("event log lock poisoned");
        conn.execute(
            "INSERT INTO events (timestamp, pid, executable, target_path, access_type, decision, reason, rule_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                timestamp,
                pid,
                executable_str,
                target_path_str,
                access_type,
                decision,
                reason,
                rule_id,
            ],
        )
        .context("failed to insert event")?;

        Ok(conn.last_insert_rowid())
    }

    /// Query recent events ordered by id descending.
    ///
    /// Up to `count` events are returned. The optional `app_filter` applies
    /// a SQL LIKE pattern to the `executable` column, and `path_filter`
    /// applies one to the `target_path` column.
    pub fn get_recent(
        &self,
        count: u32,
        app_filter: Option<&str>,
        path_filter: Option<&str>,
    ) -> Result<Vec<Event>> {
        let conn = self.conn.lock().expect("event log lock poisoned");

        // Build the WHERE clause dynamically based on supplied filters.
        let mut conditions: Vec<String> = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(app) = app_filter {
            conditions.push(format!("executable LIKE ?{}", param_values.len() + 1));
            param_values.push(Box::new(format!("%{app}%")));
        }
        if let Some(path) = path_filter {
            conditions.push(format!("target_path LIKE ?{}", param_values.len() + 1));
            param_values.push(Box::new(format!("%{path}%")));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "SELECT id, timestamp, pid, executable, target_path, access_type, decision, reason, rule_id
             FROM events {where_clause}
             ORDER BY id DESC
             LIMIT ?{}",
            param_values.len() + 1
        );

        param_values.push(Box::new(count));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql).context("failed to prepare get_recent query")?;
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let timestamp_str: String = row.get(1)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                let executable_str: String = row.get(3)?;
                let target_path_str: String = row.get(4)?;

                Ok(Event {
                    id: row.get(0)?,
                    timestamp,
                    pid: row.get(2)?,
                    executable: PathBuf::from(executable_str),
                    target_path: PathBuf::from(target_path_str),
                    access_type: row.get(5)?,
                    decision: row.get(6)?,
                    reason: row.get(7)?,
                    rule_id: row.get(8)?,
                })
            })
            .context("failed to query recent events")?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.context("failed to read event row")?);
        }
        Ok(events)
    }

    /// Return the total number of events in the database.
    pub fn get_event_count(&self) -> Result<i64> {
        let conn = self.conn.lock().expect("event log lock poisoned");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .context("failed to count events")?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Helper: create an EventLog backed by an in-memory database.
    fn memory_log() -> EventLog {
        EventLog::new(Path::new(":memory:")).expect("in-memory DB should open")
    }

    #[test]
    fn empty_log_has_zero_count() {
        let log = memory_log();
        assert_eq!(log.get_event_count().unwrap(), 0);
    }

    #[test]
    fn log_and_retrieve_event() {
        let log = memory_log();

        let id = log
            .log_event(
                1234,
                Path::new("/usr/bin/cat"),
                Path::new("/home/user/.ssh/id_rsa"),
                "read",
                "deny",
                "rule",
                Some(42),
            )
            .expect("insert should succeed");

        assert_eq!(id, 1);
        assert_eq!(log.get_event_count().unwrap(), 1);

        let events = log.get_recent(10, None, None).unwrap();
        assert_eq!(events.len(), 1);

        let ev = &events[0];
        assert_eq!(ev.id, 1);
        assert_eq!(ev.pid, 1234);
        assert_eq!(ev.executable, PathBuf::from("/usr/bin/cat"));
        assert_eq!(ev.target_path, PathBuf::from("/home/user/.ssh/id_rsa"));
        assert_eq!(ev.access_type, "read");
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "rule");
        assert_eq!(ev.rule_id, Some(42));
    }

    #[test]
    fn get_recent_respects_limit() {
        let log = memory_log();
        for i in 0..5 {
            log.log_event(
                i,
                Path::new("/usr/bin/test"),
                Path::new("/tmp/file"),
                "write",
                "allow",
                "learning",
                None,
            )
            .unwrap();
        }
        let events = log.get_recent(3, None, None).unwrap();
        assert_eq!(events.len(), 3);
        // Most recent first (highest id).
        assert_eq!(events[0].id, 5);
        assert_eq!(events[2].id, 3);
    }

    #[test]
    fn get_recent_filters_by_app() {
        let log = memory_log();
        log.log_event(1, Path::new("/usr/bin/cat"), Path::new("/tmp/a"), "read", "allow", "rule", None).unwrap();
        log.log_event(2, Path::new("/usr/bin/vim"), Path::new("/tmp/b"), "write", "deny", "rule", None).unwrap();

        let events = log.get_recent(10, Some("vim"), None).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].executable, PathBuf::from("/usr/bin/vim"));
    }

    #[test]
    fn get_recent_filters_by_path() {
        let log = memory_log();
        log.log_event(1, Path::new("/usr/bin/cat"), Path::new("/home/user/.ssh/key"), "read", "deny", "rule", None).unwrap();
        log.log_event(2, Path::new("/usr/bin/cat"), Path::new("/tmp/scratch"), "read", "allow", "not_critical", None).unwrap();

        let events = log.get_recent(10, None, Some(".ssh")).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].target_path, PathBuf::from("/home/user/.ssh/key"));
    }

    #[test]
    fn get_recent_combined_filters() {
        let log = memory_log();
        log.log_event(1, Path::new("/usr/bin/cat"), Path::new("/home/user/.ssh/key"), "read", "deny", "rule", None).unwrap();
        log.log_event(2, Path::new("/usr/bin/vim"), Path::new("/home/user/.ssh/config"), "write", "allow", "user", None).unwrap();
        log.log_event(3, Path::new("/usr/bin/cat"), Path::new("/tmp/scratch"), "read", "allow", "not_critical", None).unwrap();

        let events = log.get_recent(10, Some("vim"), Some(".ssh")).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 2);
    }

    #[test]
    fn null_rule_id_round_trips() {
        let log = memory_log();
        log.log_event(1, Path::new("/bin/sh"), Path::new("/tmp/x"), "read", "allow", "excluded", None).unwrap();

        let events = log.get_recent(1, None, None).unwrap();
        assert_eq!(events[0].rule_id, None);
    }
}
