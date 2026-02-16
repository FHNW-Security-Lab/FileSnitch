use crate::models::{Action, EventLogEntry, NewRule, PermissionKind, Rule, RuleLayer, RuleScope, now_ts};
use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create db dir {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite db {}", path.display()))?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS rules (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              executable TEXT NOT NULL,
              path TEXT NOT NULL,
              scope TEXT NOT NULL,
              permission TEXT NOT NULL,
              action TEXT NOT NULL,
              layer TEXT NOT NULL,
              expires_at INTEGER,
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp INTEGER NOT NULL,
              pid INTEGER NOT NULL,
              executable TEXT NOT NULL,
              target_path TEXT NOT NULL,
              permission TEXT NOT NULL,
              action TEXT NOT NULL,
              rule_id INTEGER,
              reason TEXT NOT NULL
            );
            "#,
        )
        .context("failed to initialize sqlite schema")?;
        Ok(())
    }

    pub fn list_rules(&self) -> anyhow::Result<Vec<Rule>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, executable, path, scope, permission, action, layer, expires_at, enabled, created_at, updated_at FROM rules",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Rule {
                id: row.get(0)?,
                executable: row.get(1)?,
                path: row.get(2)?,
                scope: decode_scope(row.get::<_, String>(3)?),
                permission: decode_permission(row.get::<_, String>(4)?),
                action: decode_action(row.get::<_, String>(5)?),
                layer: decode_layer(row.get::<_, String>(6)?),
                expires_at: row.get(7)?,
                enabled: row.get::<_, i64>(8)? != 0,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_rule(&self, id: i64) -> anyhow::Result<Option<Rule>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, executable, path, scope, permission, action, layer, expires_at, enabled, created_at, updated_at FROM rules WHERE id = ?1",
        )?;
        let row = stmt
            .query_row([id], |row| {
                Ok(Rule {
                    id: row.get(0)?,
                    executable: row.get(1)?,
                    path: row.get(2)?,
                    scope: decode_scope(row.get::<_, String>(3)?),
                    permission: decode_permission(row.get::<_, String>(4)?),
                    action: decode_action(row.get::<_, String>(5)?),
                    layer: decode_layer(row.get::<_, String>(6)?),
                    expires_at: row.get(7)?,
                    enabled: row.get::<_, i64>(8)? != 0,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn add_rule(&self, new_rule: NewRule) -> anyhow::Result<Rule> {
        let now = now_ts();
        let conn = self.conn.lock().expect("database mutex poisoned");
        conn.execute(
            "INSERT INTO rules(executable, path, scope, permission, action, layer, expires_at, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                new_rule.executable,
                new_rule.path,
                encode_scope(new_rule.scope),
                encode_permission(new_rule.permission),
                encode_action(new_rule.action),
                encode_layer(new_rule.layer),
                new_rule.expires_at,
                if new_rule.enabled { 1 } else { 0 },
                now,
                now,
            ],
        )?;
        let id = conn.last_insert_rowid();
        drop(conn);
        self.get_rule(id)
            .map(|r| r.expect("inserted rule should exist"))
    }

    pub fn update_rule(&self, rule: &Rule) -> anyhow::Result<()> {
        let now = now_ts();
        let conn = self.conn.lock().expect("database mutex poisoned");
        conn.execute(
            "UPDATE rules SET executable=?1, path=?2, scope=?3, permission=?4, action=?5, layer=?6, expires_at=?7, enabled=?8, updated_at=?9 WHERE id=?10",
            params![
                rule.executable,
                rule.path,
                encode_scope(rule.scope),
                encode_permission(rule.permission),
                encode_action(rule.action),
                encode_layer(rule.layer),
                rule.expires_at,
                if rule.enabled { 1 } else { 0 },
                now,
                rule.id,
            ],
        )?;
        Ok(())
    }

    pub fn delete_rule(&self, id: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        conn.execute("DELETE FROM rules WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn toggle_rule(&self, id: i64, enabled: bool) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        conn.execute(
            "UPDATE rules SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            params![if enabled { 1 } else { 0 }, now_ts(), id],
        )?;
        Ok(())
    }

    pub fn count_active_rules(&self) -> anyhow::Result<u64> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let count: u64 = conn.query_row(
            "SELECT COUNT(*) FROM rules WHERE enabled = 1 AND (expires_at IS NULL OR expires_at > ?1)",
            [now_ts()],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn list_events(&self, limit: u32) -> anyhow::Result<Vec<EventLogEntry>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, pid, executable, target_path, permission, action, rule_id, reason FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok(EventLogEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                pid: row.get::<_, u32>(2)?,
                executable: row.get(3)?,
                target_path: row.get(4)?,
                permission: decode_permission(row.get::<_, String>(5)?),
                action: decode_action(row.get::<_, String>(6)?),
                rule_id: row.get(7)?,
                reason: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn add_event(&self, event: &EventLogEntry) -> anyhow::Result<i64> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        conn.execute(
            "INSERT INTO events(timestamp, pid, executable, target_path, permission, action, rule_id, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.timestamp,
                event.pid,
                event.executable,
                event.target_path,
                encode_permission(event.permission),
                encode_action(event.action),
                event.rule_id,
                event.reason,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }
}

fn encode_action(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
    }
}

fn decode_action(value: String) -> Action {
    match value.as_str() {
        "allow" => Action::Allow,
        _ => Action::Deny,
    }
}

fn encode_permission(permission: PermissionKind) -> &'static str {
    match permission {
        PermissionKind::Read => "read",
        PermissionKind::Write => "write",
        PermissionKind::ReadWrite => "read_write",
    }
}

fn decode_permission(value: String) -> PermissionKind {
    match value.as_str() {
        "read" => PermissionKind::Read,
        "write" => PermissionKind::Write,
        _ => PermissionKind::ReadWrite,
    }
}

fn encode_scope(scope: RuleScope) -> &'static str {
    match scope {
        RuleScope::ExactFile => "exact_file",
        RuleScope::Folder => "folder",
        RuleScope::FolderRecursive => "folder_recursive",
        RuleScope::Home => "home",
        RuleScope::Custom => "custom",
    }
}

fn decode_scope(value: String) -> RuleScope {
    match value.as_str() {
        "exact_file" => RuleScope::ExactFile,
        "folder" => RuleScope::Folder,
        "folder_recursive" => RuleScope::FolderRecursive,
        "home" => RuleScope::Home,
        _ => RuleScope::Custom,
    }
}

fn encode_layer(layer: RuleLayer) -> &'static str {
    match layer {
        RuleLayer::Home => "home",
        RuleLayer::Critical => "critical",
    }
}

fn decode_layer(value: String) -> RuleLayer {
    match value.as_str() {
        "critical" => RuleLayer::Critical,
        _ => RuleLayer::Home,
    }
}
