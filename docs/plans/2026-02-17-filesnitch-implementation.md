# FileSnitch Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an interactive file access firewall for Linux home directories using fanotify permission events, with a Rust daemon, GTK4 GUI, and Python CLI.

**Architecture:** Three components (daemon/UI/CLI) communicating over D-Bus system bus. The Rust daemon intercepts file access via fanotify FAN_OPEN_PERM/FAN_ACCESS_PERM on a filesystem mark on /home, enforces rules from SQLite, and emits D-Bus signals for unmatched access. The Python GTK4 UI shows popup prompts and manages rules. The Python CLI provides terminal-based management.

**Tech Stack:** Rust (tokio, zbus 5, nix, rusqlite, serde, toml, tracing, sd-notify), Python 3 (PyGObject/GTK4/libadwaita, dasbus, click, rich), Nix flake packaging.

**Design doc:** `docs/plans/2026-02-17-filesnitch-design.md`

---

## Phase 1: Project Scaffolding

### Task 1: Create Cargo workspace and daemon crate

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `daemon/Cargo.toml`
- Create: `daemon/src/main.rs`

**Step 1: Create workspace Cargo.toml**

```toml
[workspace]
members = ["daemon"]
resolver = "2"
```

**Step 2: Create daemon/Cargo.toml**

```toml
[package]
name = "filesnitchd"
version = "0.1.0"
edition = "2021"
description = "FileSnitch daemon - interactive file access firewall"
license = "GPL-3.0"

[dependencies]
tokio = { version = "1", features = ["full"] }
zbus = { version = "5", default-features = false, features = ["tokio"] }
nix = { version = "0.29", features = ["fanotify", "fs", "process", "signal"] }
rusqlite = { version = "0.32", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
sd-notify = "0.4"
anyhow = "1"
chrono = { version = "0.4", features = ["serde"] }
glob-match = "0.2"

[package.metadata.deb]
maintainer = "FileSnitch Contributors"
copyright = "2026, FileSnitch Contributors"
depends = "$auto, dbus"
section = "admin"
priority = "optional"
assets = [
    ["target/release/filesnitchd", "usr/bin/", "755"],
    ["../dbus/org.filesnitch.Daemon.conf", "etc/dbus-1/system.d/", "644"],
    ["../systemd/filesnitchd.service", "lib/systemd/system/", "644"],
    ["../config/filesnitchd.toml", "etc/filesnitch/", "644"],
]
```

**Step 3: Create daemon/src/main.rs stub**

```rust
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("filesnitchd=info".parse()?),
        )
        .init();

    tracing::info!("filesnitchd starting");
    Ok(())
}
```

**Step 4: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock daemon/
git commit -m "scaffold: create Cargo workspace and daemon crate"
```

---

### Task 2: Create Python package structure

**Files:**
- Create: `shared/filesnitch_dbus/__init__.py`
- Create: `shared/filesnitch_dbus/client.py`
- Create: `shared/setup.py`
- Create: `ui/filesnitch_ui/__init__.py`
- Create: `ui/filesnitch_ui/__main__.py`
- Create: `ui/setup.py`
- Create: `cli/filesnitch_cli/__init__.py`
- Create: `cli/filesnitch_cli/__main__.py`
- Create: `cli/setup.py`

**Step 1: Create shared D-Bus client package**

`shared/setup.py`:
```python
from setuptools import setup, find_packages

setup(
    name="filesnitch-dbus",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["dasbus"],
)
```

`shared/filesnitch_dbus/__init__.py`:
```python
"""Shared D-Bus client for FileSnitch."""
```

`shared/filesnitch_dbus/client.py`:
```python
"""D-Bus client proxy for filesnitchd."""
```

**Step 2: Create UI package**

`ui/setup.py`:
```python
from setuptools import setup, find_packages

setup(
    name="filesnitch-ui",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "filesnitch-dbus",
        "PyGObject",
    ],
    entry_points={
        "gui_scripts": ["filesnitch-ui = filesnitch_ui.__main__:main"],
    },
)
```

`ui/filesnitch_ui/__init__.py`:
```python
"""FileSnitch GTK4 graphical interface."""
```

`ui/filesnitch_ui/__main__.py`:
```python
"""Entry point for filesnitch-ui."""

def main():
    print("filesnitch-ui stub")

if __name__ == "__main__":
    main()
```

**Step 3: Create CLI package**

`cli/setup.py`:
```python
from setuptools import setup, find_packages

setup(
    name="filesnitch-cli",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "filesnitch-dbus",
        "click",
        "rich",
    ],
    entry_points={
        "console_scripts": ["filesnitch = filesnitch_cli.__main__:main"],
    },
)
```

`cli/filesnitch_cli/__init__.py`:
```python
"""FileSnitch command-line interface."""
```

`cli/filesnitch_cli/__main__.py`:
```python
"""Entry point for filesnitch-cli."""

def main():
    print("filesnitch-cli stub")

if __name__ == "__main__":
    main()
```

**Step 4: Commit**

```bash
git add shared/ ui/ cli/
git commit -m "scaffold: create Python packages for shared dbus client, UI, and CLI"
```

---

### Task 3: Create config, D-Bus policy, and systemd unit files

**Files:**
- Create: `config/filesnitchd.toml`
- Create: `dbus/org.filesnitch.Daemon.conf`
- Create: `dbus/org.filesnitch.Daemon.service`
- Create: `systemd/filesnitchd.service`

**Step 1: Create default config**

`config/filesnitchd.toml`:
```toml
[general]
# "learning" or "enforce"
operation_mode = "learning"
# "critical_only" or "everything"
protection_mode = "critical_only"
# "deny" or "allow"
default_action = "deny"
# Seconds before auto-applying default action
prompt_timeout = 30
# Path to the SQLite database
db_path = "/var/lib/filesnitchd/rules.db"
# Log level: "error", "warn", "info", "debug", "trace"
log_level = "info"

[critical_paths]
paths = [
    ".ssh",
    ".gnupg",
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".aws",
    ".kube",
    ".gitconfig",
    ".config/git",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
    ".thunderbird",
    ".config/Code",
]

[excluded_executables]
# Additional user-defined exclusions (beyond built-in list)
paths = []
```

**Step 2: Create D-Bus policy file**

`dbus/org.filesnitch.Daemon.conf`:
```xml
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.filesnitch.Daemon"/>
    <allow send_destination="org.filesnitch.Daemon"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.filesnitch.Daemon"/>
    <allow receive_sender="org.filesnitch.Daemon"/>
  </policy>
</busconfig>
```

**Step 3: Create D-Bus service activation file**

`dbus/org.filesnitch.Daemon.service`:
```ini
[D-BUS Service]
Name=org.filesnitch.Daemon
Exec=/usr/bin/filesnitchd
User=root
SystemdService=filesnitchd.service
```

**Step 4: Create systemd unit**

`systemd/filesnitchd.service`:
```ini
[Unit]
Description=FileSnitch File Access Firewall Daemon
After=dbus.service
Requires=dbus.service

[Service]
Type=notify
ExecStart=/usr/bin/filesnitchd
Restart=on-failure
RestartSec=5
WatchdogSec=30
# Prevent restart storms
StartLimitIntervalSec=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
Also=dbus-org.filesnitch.Daemon.service
```

**Step 5: Commit**

```bash
git add config/ dbus/ systemd/
git commit -m "scaffold: add config, D-Bus policy, and systemd unit files"
```

---

## Phase 2: Daemon Core Types and Config

### Task 4: Implement config module

**Files:**
- Create: `daemon/src/config.rs`
- Modify: `daemon/src/main.rs`

**Step 1: Write config.rs**

```rust
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub critical_paths: CriticalPathsConfig,
    pub excluded_executables: ExcludedExecutablesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub operation_mode: OperationMode,
    pub protection_mode: ProtectionMode,
    pub default_action: DefaultAction,
    pub prompt_timeout: u32,
    pub db_path: PathBuf,
    pub log_level: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    Learning,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    CriticalOnly,
    Everything,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalPathsConfig {
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludedExecutablesConfig {
    pub paths: Vec<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| "failed to parse config TOML")?;
        Ok(config)
    }

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
                    ".ssh".into(),
                    ".gnupg".into(),
                    ".bashrc".into(),
                    ".zshrc".into(),
                    ".profile".into(),
                    ".bash_profile".into(),
                    ".aws".into(),
                    ".kube".into(),
                    ".gitconfig".into(),
                    ".config/git".into(),
                    ".mozilla".into(),
                    ".config/google-chrome".into(),
                    ".config/chromium".into(),
                    ".thunderbird".into(),
                    ".config/Code".into(),
                ],
            },
            excluded_executables: ExcludedExecutablesConfig { paths: vec![] },
        }
    }
}
```

**Step 2: Wire config into main.rs**

```rust
mod config;

use anyhow::Result;
use config::Config;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("filesnitchd=info".parse()?),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(Config::default_path);

    let config = if config_path.exists() {
        Config::load(&config_path)?
    } else {
        tracing::warn!("config file not found at {}, using defaults", config_path.display());
        Config::default()
    };

    tracing::info!(
        mode = ?config.general.operation_mode,
        protection = ?config.general.protection_mode,
        "filesnitchd starting"
    );

    Ok(())
}
```

**Step 3: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS

**Step 4: Verify config parsing works**

Run: `cargo run -p filesnitchd -- config/filesnitchd.toml`
Expected: log output showing "filesnitchd starting" with mode=Learning, protection=CriticalOnly

**Step 5: Commit**

```bash
git add daemon/src/config.rs daemon/src/main.rs
git commit -m "feat(daemon): add config module with TOML parsing"
```

---

### Task 5: Implement process_info module

**Files:**
- Create: `daemon/src/process_info.rs`
- Modify: `daemon/src/main.rs` (add `mod process_info;`)

**Step 1: Write process_info.rs**

```rust
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Cached process information resolver.
pub struct ProcessInfoCache {
    cache: Mutex<HashMap<i32, ProcessInfo>>,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub executable: PathBuf,
    pub cmdline: String,
    pub uid: u32,
    pub comm: String,
}

impl ProcessInfoCache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, pid: i32) -> Option<ProcessInfo> {
        self.cache.lock().unwrap().get(&pid).cloned()
    }

    pub fn resolve(&self, pid: i32) -> Result<ProcessInfo> {
        if let Some(info) = self.get(pid) {
            return Ok(info);
        }

        let info = ProcessInfo::from_pid(pid)?;
        self.cache.lock().unwrap().insert(pid, info.clone());
        Ok(info)
    }

    /// Remove stale entries for PIDs that no longer exist.
    pub fn cleanup(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|pid, _| PathBuf::from(format!("/proc/{}", pid)).exists());
    }
}

impl ProcessInfo {
    pub fn from_pid(pid: i32) -> Result<Self> {
        let proc_dir = format!("/proc/{}", pid);

        let executable = std::fs::read_link(format!("{}/exe", proc_dir))
            .unwrap_or_else(|_| PathBuf::from("<unknown>"));

        let cmdline = std::fs::read_to_string(format!("{}/cmdline", proc_dir))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let status = std::fs::read_to_string(format!("{}/status", proc_dir))
            .with_context(|| format!("failed to read /proc/{}/status", pid))?;

        let uid = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|uid_str| uid_str.parse::<u32>().ok())
            .unwrap_or(u32::MAX);

        let comm = std::fs::read_to_string(format!("{}/comm", proc_dir))
            .unwrap_or_default()
            .trim()
            .to_string();

        Ok(Self {
            pid,
            executable,
            cmdline,
            uid,
            comm,
        })
    }

    /// Check if this process is running under system.slice cgroup.
    pub fn is_system_service(&self) -> bool {
        let cgroup_path = format!("/proc/{}/cgroup", self.pid);
        std::fs::read_to_string(cgroup_path)
            .map(|content| content.contains("system.slice"))
            .unwrap_or(false)
    }
}

/// Resolve the file path from a fanotify event fd.
pub fn resolve_fd_path(fd: i32) -> Result<PathBuf> {
    let link = format!("/proc/self/fd/{}", fd);
    std::fs::read_link(&link).with_context(|| format!("failed to readlink {}", link))
}
```

**Step 2: Add mod to main.rs**

Add `mod process_info;` after `mod config;` in `daemon/src/main.rs`.

**Step 3: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS

**Step 4: Commit**

```bash
git add daemon/src/process_info.rs daemon/src/main.rs
git commit -m "feat(daemon): add process info resolver with /proc lookups and caching"
```

---

### Task 6: Implement exclusions module

**Files:**
- Create: `daemon/src/exclusions.rs`
- Modify: `daemon/src/main.rs` (add `mod exclusions;`)

**Step 1: Write exclusions.rs**

```rust
use crate::config::Config;
use crate::process_info::ProcessInfo;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Built-in exclusion list that cannot be removed by users.
pub struct ExclusionList {
    builtin_executables: HashSet<PathBuf>,
    builtin_prefixes: Vec<PathBuf>,
    user_executables: HashSet<PathBuf>,
    min_uid: u32,
}

impl ExclusionList {
    pub fn new(config: &Config) -> Self {
        let mut builtin = HashSet::new();
        let prefixes = vec![
            PathBuf::from("/usr/lib/systemd"),
            PathBuf::from("/run/current-system"),
            PathBuf::from("/nix/store"),
        ];

        // Shells
        for shell in &[
            "/bin/bash", "/bin/zsh", "/bin/fish", "/bin/sh",
            "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/fish", "/usr/bin/sh",
        ] {
            builtin.insert(PathBuf::from(shell));
        }

        // D-Bus
        for bin in &["/usr/bin/dbus-daemon", "/usr/bin/dbus-broker", "/usr/bin/dbus-broker-launch"] {
            builtin.insert(PathBuf::from(bin));
        }

        // Display servers
        for bin in &[
            "/usr/bin/Xorg", "/usr/bin/Xwayland",
            "/usr/bin/sway", "/usr/bin/mutter", "/usr/bin/kwin_wayland",
            "/usr/bin/gnome-shell", "/usr/bin/plasmashell",
        ] {
            builtin.insert(PathBuf::from(bin));
        }

        // Auth
        for bin in &[
            "/usr/bin/login", "/usr/bin/su", "/usr/bin/sudo",
            "/usr/bin/polkitd", "/usr/lib/polkit-1/polkitd",
        ] {
            builtin.insert(PathBuf::from(bin));
        }

        // Package managers
        for bin in &[
            "/usr/bin/nix", "/usr/bin/dpkg", "/usr/bin/apt",
            "/usr/bin/apt-get", "/usr/bin/pacman", "/usr/bin/rpm",
        ] {
            builtin.insert(PathBuf::from(bin));
        }

        // Agents & keyring
        for bin in &[
            "/usr/bin/gpg-agent", "/usr/bin/ssh-agent",
            "/usr/bin/gnome-keyring-daemon", "/usr/bin/secret-tool",
        ] {
            builtin.insert(PathBuf::from(bin));
        }

        // Audio/video
        for bin in &[
            "/usr/bin/pipewire", "/usr/bin/wireplumber",
            "/usr/bin/pulseaudio", "/usr/bin/pactl",
        ] {
            builtin.insert(PathBuf::from(bin));
        }

        // System services
        for bin in &[
            "/usr/bin/systemd-resolved", "/usr/lib/systemd/systemd-journald",
            "/usr/lib/systemd/systemd-logind", "/usr/bin/NetworkManager",
            "/usr/sbin/cron", "/usr/sbin/crond",
        ] {
            builtin.insert(PathBuf::from(bin));
        }

        // FileSnitch itself
        for bin in &["/usr/bin/filesnitchd", "/usr/bin/filesnitch-ui", "/usr/bin/filesnitch"] {
            builtin.insert(PathBuf::from(bin));
        }

        let user_execs = config
            .excluded_executables
            .paths
            .iter()
            .cloned()
            .collect();

        Self {
            builtin_executables: builtin,
            builtin_prefixes: prefixes,
            user_executables: user_execs,
            min_uid: 1000,
        }
    }

    /// Check if a process should be excluded from prompting.
    pub fn is_excluded(&self, info: &ProcessInfo) -> bool {
        // System users (UID < 1000)
        if info.uid < self.min_uid {
            return true;
        }

        // System services (cgroup check)
        if info.is_system_service() {
            return true;
        }

        // Built-in executable list
        if self.builtin_executables.contains(&info.executable) {
            return true;
        }

        // Built-in prefix list (for NixOS, systemd paths)
        for prefix in &self.builtin_prefixes {
            if info.executable.starts_with(prefix) {
                return true;
            }
        }

        // User-defined exclusions
        if self.user_executables.contains(&info.executable) {
            return true;
        }

        false
    }

    /// Add a user-defined exclusion.
    pub fn add_user_exclusion(&mut self, path: PathBuf) {
        self.user_executables.insert(path);
    }

    /// Remove a user-defined exclusion. Cannot remove built-in entries.
    pub fn remove_user_exclusion(&mut self, path: &Path) -> bool {
        self.user_executables.remove(path)
    }

    pub fn user_exclusions(&self) -> Vec<PathBuf> {
        self.user_executables.iter().cloned().collect()
    }
}
```

**Step 2: Add mod to main.rs**

Add `mod exclusions;` to `daemon/src/main.rs`.

**Step 3: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS

**Step 4: Commit**

```bash
git add daemon/src/exclusions.rs daemon/src/main.rs
git commit -m "feat(daemon): add built-in exclusion list for system processes"
```

---

## Phase 3: Rule Store and Event Log

### Task 7: Implement rule store with SQLite

**Files:**
- Create: `daemon/src/rules.rs`
- Modify: `daemon/src/main.rs` (add `mod rules;`)

**Step 1: Write rules.rs**

This module manages the SQLite rule database and in-memory cache. Key types:

```rust
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy)]
pub enum AccessType {
    Read,
    Write,
}
```

The `RuleStore` struct wraps a `Mutex<Connection>` and an in-memory `HashMap<String, Vec<Rule>>` cache keyed by executable path string. It provides:

- `new(db_path)` — opens/creates SQLite DB, runs CREATE TABLE IF NOT EXISTS, loads rules into cache
- `find_matching_rule(executable, target_path, access_type)` — checks cache for a matching non-expired rule, using priority: critical rules first, then exact path > folder glob > recursive glob > home-wide. Deny beats allow at same specificity.
- `add_rule(rule)` — inserts into SQLite and updates cache, returns rule ID
- `edit_rule(id, changes)` — updates SQLite and cache
- `delete_rule(id)` — removes from SQLite and cache
- `list_rules(filter)` — returns all rules, optionally filtered
- `record_hit(id)` — increments hit_count and updates last_hit_at
- `cleanup_expired()` — removes expired rules from cache and SQLite
- `export_json()` / `import_json(json)` — for rule import/export

**Path matching logic in `find_matching_rule`:**
1. Find all rules for the given executable
2. Filter by permission compatibility (read rule matches read access, readwrite matches both)
3. Filter out expired rules
4. Filter out disabled rules
5. Sort by specificity: is_critical DESC, then path specificity (exact > folder/* > folder/** > home/**)
6. For rules at the same specificity, deny wins over allow
7. Return the first (highest priority) match

**SQLite schema** (run in `new()`):
```sql
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    executable TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    permission TEXT NOT NULL,
    action TEXT NOT NULL,
    is_critical INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_hit_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_rules_executable ON rules(executable);
CREATE INDEX IF NOT EXISTS idx_rules_expires ON rules(expires_at);
```

**Step 2: Add mod to main.rs**

Add `mod rules;` to `daemon/src/main.rs`.

**Step 3: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS

**Step 4: Commit**

```bash
git add daemon/src/rules.rs daemon/src/main.rs
git commit -m "feat(daemon): add rule store with SQLite persistence and in-memory cache"
```

---

### Task 8: Implement event log module

**Files:**
- Create: `daemon/src/event_log.rs`
- Modify: `daemon/src/main.rs` (add `mod event_log;`)

**Step 1: Write event_log.rs**

```rust
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub pid: i32,
    pub executable: PathBuf,
    pub target_path: PathBuf,
    pub access_type: String,
    pub decision: String,
    pub reason: String,
    pub rule_id: Option<i64>,
}

pub struct EventLog {
    conn: Mutex<Connection>,
}

impl EventLog {
    pub fn new(conn: &Mutex<Connection>) -> Result<Self> {
        let db = conn.lock().unwrap();
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                pid INTEGER NOT NULL,
                executable TEXT NOT NULL,
                target_path TEXT NOT NULL,
                access_type TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                rule_id INTEGER REFERENCES rules(id)
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_executable ON events(executable);"
        ).context("failed to create events table")?;
        drop(db);

        // EventLog shares the same connection
        // In practice, we'll pass the connection from RuleStore
        // For now, create a stub that takes its own path
        Ok(Self {
            conn: Mutex::new(Connection::open_in_memory()?),
        })
    }

    /// Log an access event.
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
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO events (timestamp, pid, executable, target_path, access_type, decision, reason, rule_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                now,
                pid,
                executable.to_string_lossy(),
                target_path.to_string_lossy(),
                access_type,
                decision,
                reason,
                rule_id,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get recent events, newest first.
    pub fn get_recent(&self, count: u32, app_filter: Option<&str>, path_filter: Option<&str>) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let mut sql = String::from(
            "SELECT id, timestamp, pid, executable, target_path, access_type, decision, reason, rule_id
             FROM events WHERE 1=1"
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];

        if let Some(app) = app_filter {
            sql.push_str(" AND executable LIKE ?");
            param_values.push(Box::new(format!("%{}%", app)));
        }
        if let Some(path) = path_filter {
            sql.push_str(" AND target_path LIKE ?");
            param_values.push(Box::new(format!("%{}%", path)));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        param_values.push(Box::new(count));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql)?;
        let events = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok(Event {
                    id: row.get(0)?,
                    timestamp: row.get::<_, String>(1)?.parse().unwrap_or_default(),
                    pid: row.get(2)?,
                    executable: PathBuf::from(row.get::<_, String>(3)?),
                    target_path: PathBuf::from(row.get::<_, String>(4)?),
                    access_type: row.get(5)?,
                    decision: row.get(6)?,
                    reason: row.get(7)?,
                    rule_id: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }
}

use std::path::Path;
```

Note: In the final integration (Task 12), the EventLog and RuleStore will share a single SQLite connection. For now they are independent modules.

**Step 2: Add mod to main.rs**

Add `mod event_log;` to `daemon/src/main.rs`.

**Step 3: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS

**Step 4: Commit**

```bash
git add daemon/src/event_log.rs daemon/src/main.rs
git commit -m "feat(daemon): add event logging to SQLite"
```

---

## Phase 4: Daemon Fanotify

### Task 9: Implement fanotify module

**Files:**
- Create: `daemon/src/fanotify.rs`
- Modify: `daemon/src/main.rs` (add `mod fanotify;`)

**Step 1: Write fanotify.rs**

This wraps the nix crate's fanotify API and runs the blocking event-reading thread.

```rust
use anyhow::{Context, Result};
use nix::sys::fanotify::{
    EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags, Response,
};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// A fanotify permission event to be decided on.
#[derive(Debug)]
pub struct FanotifyEvent {
    /// Unique request ID for tracking.
    pub request_id: u64,
    /// PID of the process that triggered the event.
    pub pid: i32,
    /// The raw fd from the event (for responding).
    pub event_fd: i32,
    /// The target file path being accessed.
    pub target_path: PathBuf,
    /// Whether this is a read or write access.
    pub access_type: AccessType,
}

#[derive(Debug, Clone, Copy)]
pub enum AccessType {
    Read,
    Write,
}

/// Response to send back to fanotify.
pub struct FanotifyDecision {
    pub event_fd: i32,
    pub allow: bool,
}

/// Initialize fanotify and place a filesystem mark on /home.
pub fn init_fanotify() -> Result<Fanotify> {
    let fan = Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_CONTENT,
        EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC,
    )
    .context("fanotify_init failed - are you running as root?")?;

    fan.mark(
        MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
        MaskFlags::FAN_OPEN_PERM | MaskFlags::FAN_ACCESS_PERM,
        None,
        Some(&Path::new("/home")),
    )
    .context("fanotify_mark on /home failed")?;

    tracing::info!("fanotify initialized with filesystem mark on /home");
    Ok(fan)
}

/// Spawn a blocking thread that reads fanotify events and sends them to the async decision engine.
/// Returns a channel receiver for events and a handle to the thread.
pub fn spawn_event_reader(
    fan: Fanotify,
    event_tx: mpsc::Sender<FanotifyEvent>,
) -> std::thread::JoinHandle<()> {
    let mut next_request_id: u64 = 1;

    std::thread::Builder::new()
        .name("fanotify-reader".to_string())
        .spawn(move || {
            tracing::info!("fanotify reader thread started");
            loop {
                match fan.read_events() {
                    Ok(events) => {
                        for event in events {
                            if !event.check_version() {
                                tracing::warn!("fanotify event version mismatch, skipping");
                                continue;
                            }

                            let fd = match event.fd() {
                                Some(fd) => fd,
                                None => {
                                    tracing::debug!("queue overflow event, skipping");
                                    continue;
                                }
                            };

                            let raw_fd = fd.as_raw_fd();
                            let target_path = resolve_event_fd(raw_fd);
                            let mask = event.mask();

                            let access_type = if mask.contains(MaskFlags::FAN_ACCESS_PERM) {
                                AccessType::Read
                            } else {
                                AccessType::Write // FAN_OPEN_PERM - could be read or write
                            };

                            let request_id = next_request_id;
                            next_request_id += 1;

                            let fan_event = FanotifyEvent {
                                request_id,
                                pid: event.pid(),
                                event_fd: raw_fd,
                                target_path,
                                access_type,
                            };

                            // Send to decision engine. If channel is full/closed, allow the access
                            // to prevent process hangs.
                            if event_tx.blocking_send(fan_event).is_err() {
                                tracing::error!("decision engine channel closed, auto-allowing");
                                let _ = write_fanotify_response(raw_fd, true);
                            }
                        }
                    }
                    Err(e) => {
                        if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EINTR {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        tracing::error!("fanotify read error: {}", e);
                        break;
                    }
                }
            }
        })
        .expect("failed to spawn fanotify reader thread")
}

fn resolve_event_fd(fd: i32) -> PathBuf {
    let link = format!("/proc/self/fd/{}", fd);
    std::fs::read_link(&link).unwrap_or_else(|_| PathBuf::from("<unknown>"))
}

/// Write an allow/deny response back to fanotify.
pub fn write_fanotify_response(event_fd: i32, allow: bool) -> Result<()> {
    let response = if allow {
        Response::Allow
    } else {
        Response::Deny
    };

    // We need to write the fanotify_response struct to the fanotify fd.
    // The nix crate's Fanotify::write_response handles this, but we need the
    // Fanotify object. Instead, we'll write directly using libc.
    let resp = libc::fanotify_response {
        fd: event_fd,
        response: if allow {
            libc::FAN_ALLOW as u32
        } else {
            libc::FAN_DENY as u32
        },
    };

    // The fanotify fd is needed to write responses. We'll restructure this
    // in integration to pass the Fanotify object through.
    // For now, this is a placeholder showing the response structure.
    Ok(())
}
```

Note: The response writing will be restructured in Task 12 (main integration) to pass the Fanotify object properly. The fanotify fd is needed for `write_response()`, not the event fd. The event's BorrowedFd is used to construct a `FanotifyResponse` which is then written via `Fanotify::write_response()`.

**Step 2: Add mod and libc dependency**

Add `mod fanotify;` to `daemon/src/main.rs`.
Add `libc = "0.2"` to `daemon/Cargo.toml` dependencies.

**Step 3: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS

**Step 4: Commit**

```bash
git add daemon/src/fanotify.rs daemon/src/main.rs daemon/Cargo.toml
git commit -m "feat(daemon): add fanotify module with event reading thread"
```

---

## Phase 5: Decision Engine

### Task 10: Implement decision engine

**Files:**
- Create: `daemon/src/decision.rs`
- Modify: `daemon/src/main.rs` (add `mod decision;`)

**Step 1: Write decision.rs**

The decision engine is the core async loop. It receives fanotify events, checks exclusions and rules, emits D-Bus signals for unmatched events, and handles timeout.

```rust
use crate::config::{Config, DefaultAction, OperationMode, ProtectionMode};
use crate::exclusions::ExclusionList;
use crate::fanotify::{AccessType, FanotifyEvent};
use crate::process_info::ProcessInfoCache;
use crate::rules::{Action, RuleStore};
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};

/// A pending permission request waiting for a user decision.
#[derive(Debug)]
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

/// The user's decision from the UI or CLI.
#[derive(Debug, Clone)]
pub struct UserDecision {
    pub action: Action,
    pub duration: String,
    pub path_scope: String,
    pub permission: String,
}

/// The decision engine state.
pub struct DecisionEngine {
    pub config: Arc<RwLock<Config>>,
    pub rules: Arc<RuleStore>,
    pub exclusions: Arc<RwLock<ExclusionList>>,
    pub process_cache: Arc<ProcessInfoCache>,
    pub pending_requests: Arc<RwLock<HashMap<u64, PendingRequest>>>,
}

impl DecisionEngine {
    pub fn new(
        config: Arc<RwLock<Config>>,
        rules: Arc<RuleStore>,
        exclusions: Arc<RwLock<ExclusionList>>,
        process_cache: Arc<ProcessInfoCache>,
    ) -> Self {
        Self {
            config,
            rules,
            exclusions,
            process_cache,
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Process a single fanotify event. Returns (allow: bool, reason: &str).
    pub async fn decide(&self, event: &FanotifyEvent) -> (bool, String) {
        // 1. Resolve process info
        let proc_info = match self.process_cache.resolve(event.pid) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!(pid = event.pid, "failed to resolve process info: {}", e);
                return (true, "process_gone".to_string());
            }
        };

        // 2. Check exclusions
        if self.exclusions.read().await.is_excluded(&proc_info) {
            return (true, "excluded".to_string());
        }

        let config = self.config.read().await;

        // 3. Check if target is under /home
        if !event.target_path.starts_with("/home") {
            return (true, "not_home".to_string());
        }

        // 4. Learning mode: allow everything but log
        if config.general.operation_mode == OperationMode::Learning {
            return (true, "learning".to_string());
        }

        // 5. Check protection mode
        if config.general.protection_mode == ProtectionMode::CriticalOnly {
            if !self.is_critical_path(&event.target_path, &config.critical_paths.paths) {
                return (true, "not_critical".to_string());
            }
        }

        let access = match event.access_type {
            AccessType::Read => crate::rules::AccessType::Read,
            AccessType::Write => crate::rules::AccessType::Write,
        };

        // 6. Check rule store
        if let Some(rule) = self.rules.find_matching_rule(
            &proc_info.executable,
            &event.target_path,
            access,
        ) {
            let allow = rule.action == Action::Allow;
            self.rules.record_hit(rule.id).ok();
            return (allow, format!("rule:{}", rule.id));
        }

        let timeout = config.general.prompt_timeout;
        let default_action = config.general.default_action;
        drop(config);

        // 7. No matching rule — need user decision
        // Create a oneshot channel for the response
        let (tx, rx) = oneshot::channel();
        let request_id = event.request_id;

        let pending = PendingRequest {
            request_id,
            pid: event.pid,
            executable: proc_info.executable.to_string_lossy().to_string(),
            target_path: event.target_path.to_string_lossy().to_string(),
            access_type: format!("{:?}", event.access_type).to_lowercase(),
            app_name: proc_info.comm.clone(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            response_tx: tx,
        };

        self.pending_requests.write().await.insert(request_id, pending);

        // 8. Emit D-Bus signal (handled externally by the D-Bus interface)
        // The D-Bus interface polls pending_requests and emits signals.

        // 9. Wait for response or timeout
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout as u64),
            rx,
        )
        .await
        {
            Ok(Ok(decision)) => {
                // User responded — create rule if duration > once
                let allow = decision.action == Action::Allow;
                if decision.duration != "once" {
                    // Create a new rule from the decision
                    // (implementation in integration task)
                }
                (allow, "user".to_string())
            }
            Ok(Err(_)) => {
                // Sender dropped (shouldn't happen)
                self.pending_requests.write().await.remove(&request_id);
                let allow = matches!(default_action, crate::config::DefaultAction::Allow);
                (allow, "timeout".to_string())
            }
            Err(_) => {
                // Timeout
                self.pending_requests.write().await.remove(&request_id);
                let allow = matches!(default_action, crate::config::DefaultAction::Allow);
                (allow, "timeout".to_string())
            }
        }
    }

    fn is_critical_path(&self, target: &Path, critical_paths: &[String]) -> bool {
        let target_str = target.to_string_lossy();
        for critical in critical_paths {
            // Check if any path component after /home/<user>/ matches
            // e.g., critical = ".ssh" matches /home/user/.ssh/anything
            if let Some(home_relative) = target_str
                .strip_prefix("/home/")
                .and_then(|p| p.split_once('/').map(|(_, rest)| rest))
            {
                if home_relative.starts_with(critical) {
                    return true;
                }
            }
        }
        false
    }
}
```

**Step 2: Add mod to main.rs**

Add `mod decision;` to `daemon/src/main.rs`.

**Step 3: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS

**Step 4: Commit**

```bash
git add daemon/src/decision.rs daemon/src/main.rs
git commit -m "feat(daemon): add decision engine with rule matching and timeout handling"
```

---

## Phase 6: D-Bus Interface

### Task 11: Implement D-Bus interface

**Files:**
- Create: `daemon/src/dbus_interface.rs`
- Modify: `daemon/src/main.rs` (add `mod dbus_interface;`)

**Step 1: Write dbus_interface.rs**

Uses the zbus `#[interface]` macro to expose the daemon's D-Bus API.

```rust
use crate::config::{Config, OperationMode, ProtectionMode};
use crate::decision::{DecisionEngine, UserDecision};
use crate::rules::{Action, RuleStore};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zbus::{interface, SignalContext};

pub struct FilesnitchInterface {
    pub engine: Arc<DecisionEngine>,
    pub config: Arc<RwLock<Config>>,
    pub rules: Arc<RuleStore>,
}

#[interface(name = "org.filesnitch.Daemon")]
impl FilesnitchInterface {
    /// Respond to a pending permission request.
    async fn respond_to_request(
        &self,
        request_id: u64,
        action: &str,
        duration: &str,
        path_scope: &str,
        permission: &str,
    ) -> zbus::fdo::Result<()> {
        let action_enum = match action {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            _ => return Err(zbus::fdo::Error::InvalidArgs("action must be allow or deny".into())),
        };

        let decision = UserDecision {
            action: action_enum,
            duration: duration.to_string(),
            path_scope: path_scope.to_string(),
            permission: permission.to_string(),
        };

        let mut pending = self.engine.pending_requests.write().await;
        if let Some(req) = pending.remove(&request_id) {
            let _ = req.response_tx.send(decision);
            Ok(())
        } else {
            Err(zbus::fdo::Error::InvalidArgs("no pending request with that ID".into()))
        }
    }

    /// List all rules, optionally filtered.
    async fn list_rules(
        &self,
        filter: HashMap<String, zbus::zvariant::Value<'_>>,
    ) -> zbus::fdo::Result<Vec<HashMap<String, zbus::zvariant::OwnedValue>>> {
        let rules = self.rules.list_rules(None)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let result: Vec<HashMap<String, zbus::zvariant::OwnedValue>> = rules
            .into_iter()
            .map(|r| rule_to_dict(&r))
            .collect();

        Ok(result)
    }

    /// Add a new rule.
    async fn add_rule(
        &self,
        rule: HashMap<String, zbus::zvariant::Value<'_>>,
    ) -> zbus::fdo::Result<u64> {
        // Parse rule from dict and add to store
        // (Full implementation extracts fields from the HashMap)
        Err(zbus::fdo::Error::Failed("not yet implemented".into()))
    }

    /// Delete a rule by ID.
    async fn delete_rule(&self, rule_id: u64) -> zbus::fdo::Result<()> {
        self.rules
            .delete_rule(rule_id as i64)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Export all rules as JSON.
    async fn export_rules(&self) -> zbus::fdo::Result<String> {
        self.rules
            .export_json()
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Import rules from JSON.
    async fn import_rules(&self, json: &str) -> zbus::fdo::Result<u32> {
        self.rules
            .import_json(json)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Get recent events.
    async fn get_recent_events(
        &self,
        count: u32,
        filter: HashMap<String, zbus::zvariant::Value<'_>>,
    ) -> zbus::fdo::Result<Vec<HashMap<String, zbus::zvariant::OwnedValue>>> {
        // Returns events from the event log
        Ok(vec![])
    }

    /// Get daemon configuration.
    async fn get_config(&self) -> zbus::fdo::Result<HashMap<String, zbus::zvariant::OwnedValue>> {
        let config = self.config.read().await;
        let mut map = HashMap::new();
        map.insert(
            "operation_mode".to_string(),
            zbus::zvariant::Value::from(format!("{:?}", config.general.operation_mode)).try_into().unwrap(),
        );
        map.insert(
            "protection_mode".to_string(),
            zbus::zvariant::Value::from(format!("{:?}", config.general.protection_mode)).try_into().unwrap(),
        );
        map.insert(
            "default_action".to_string(),
            zbus::zvariant::Value::from(format!("{:?}", config.general.default_action)).try_into().unwrap(),
        );
        map.insert(
            "prompt_timeout".to_string(),
            zbus::zvariant::Value::from(config.general.prompt_timeout).try_into().unwrap(),
        );
        Ok(map)
    }

    /// Set a config value.
    async fn set_config(&self, key: &str, value: &str) -> zbus::fdo::Result<()> {
        let mut config = self.config.write().await;
        match key {
            "operation_mode" => {
                config.general.operation_mode = match value {
                    "learning" => OperationMode::Learning,
                    "enforce" => OperationMode::Enforce,
                    _ => return Err(zbus::fdo::Error::InvalidArgs("invalid operation mode".into())),
                };
            }
            "protection_mode" => {
                config.general.protection_mode = match value {
                    "critical_only" => ProtectionMode::CriticalOnly,
                    "everything" => ProtectionMode::Everything,
                    _ => return Err(zbus::fdo::Error::InvalidArgs("invalid protection mode".into())),
                };
            }
            "prompt_timeout" => {
                config.general.prompt_timeout = value
                    .parse()
                    .map_err(|_| zbus::fdo::Error::InvalidArgs("invalid timeout value".into()))?;
            }
            _ => return Err(zbus::fdo::Error::InvalidArgs(format!("unknown config key: {}", key))),
        }
        Ok(())
    }

    /// Get daemon status.
    async fn get_status(&self) -> zbus::fdo::Result<HashMap<String, zbus::zvariant::OwnedValue>> {
        let config = self.config.read().await;
        let pending_count = self.engine.pending_requests.read().await.len();
        let mut map = HashMap::new();
        map.insert(
            "operation_mode".to_string(),
            zbus::zvariant::Value::from(format!("{:?}", config.general.operation_mode)).try_into().unwrap(),
        );
        map.insert(
            "protection_mode".to_string(),
            zbus::zvariant::Value::from(format!("{:?}", config.general.protection_mode)).try_into().unwrap(),
        );
        map.insert(
            "pending_requests".to_string(),
            zbus::zvariant::Value::from(pending_count as u32).try_into().unwrap(),
        );
        Ok(map)
    }

    /// Get the critical paths list.
    async fn get_critical_paths(&self) -> zbus::fdo::Result<Vec<String>> {
        let config = self.config.read().await;
        Ok(config.critical_paths.paths.clone())
    }

    /// Add a critical path.
    async fn add_critical_path(&self, path: &str) -> zbus::fdo::Result<()> {
        let mut config = self.config.write().await;
        if !config.critical_paths.paths.contains(&path.to_string()) {
            config.critical_paths.paths.push(path.to_string());
        }
        Ok(())
    }

    /// Remove a critical path.
    async fn remove_critical_path(&self, path: &str) -> zbus::fdo::Result<()> {
        let mut config = self.config.write().await;
        config.critical_paths.paths.retain(|p| p != path);
        Ok(())
    }

    // --- Signals ---

    /// Emitted when a permission request needs user input.
    #[zbus(signal)]
    async fn permission_request(
        ctxt: &SignalContext<'_>,
        request_id: u64,
        pid: u32,
        executable: &str,
        target_path: &str,
        access_type: &str,
        app_name: &str,
        timestamp: u64,
    ) -> zbus::Result<()>;

    /// Emitted when a rule changes.
    #[zbus(signal)]
    async fn rule_changed(
        ctxt: &SignalContext<'_>,
        rule_id: u64,
        change_type: &str,
    ) -> zbus::Result<()>;

    /// Emitted when an event is logged.
    #[zbus(signal)]
    async fn event_logged(
        ctxt: &SignalContext<'_>,
        event: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::Result<()>;
}

fn rule_to_dict(rule: &crate::rules::Rule) -> HashMap<String, zbus::zvariant::OwnedValue> {
    let mut map = HashMap::new();
    // Convert rule fields to OwnedValue entries
    // (implementation fills in all fields)
    map
}
```

**Step 2: Add mod to main.rs**

Add `mod dbus_interface;` to `daemon/src/main.rs`.

**Step 3: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS (may need adjustments to zbus types)

**Step 4: Commit**

```bash
git add daemon/src/dbus_interface.rs daemon/src/main.rs
git commit -m "feat(daemon): add D-Bus interface with zbus for all API methods and signals"
```

---

## Phase 7: Daemon Main Integration

### Task 12: Wire everything together in main.rs

**Files:**
- Modify: `daemon/src/main.rs`
- Modify: `daemon/src/fanotify.rs` (fix response writing)

**Step 1: Update main.rs to integrate all modules**

The main function should:
1. Parse config
2. Initialize tracing with configured log level
3. Open/create SQLite database directory
4. Create shared state: `Arc<RwLock<Config>>`, `Arc<RuleStore>`, `Arc<RwLock<ExclusionList>>`, `Arc<ProcessInfoCache>`
5. Create `DecisionEngine`
6. Initialize fanotify (if running as root, otherwise warn and run in D-Bus-only mode for development)
7. Set up D-Bus connection on system bus with `org.filesnitch.Daemon` name
8. Serve the `FilesnitchInterface` at `/org/filesnitch/Daemon`
9. Send `sd_notify::notify(true, &[NotifyState::Ready])`
10. Spawn main event loop: read from fanotify event channel, call `engine.decide()`, write fanotify response, emit D-Bus signals for pending requests
11. Spawn watchdog task: every 10s send `NotifyState::Watchdog`
12. Spawn cleanup task: every 60s call `rules.cleanup_expired()` and `process_cache.cleanup()`
13. Handle SIGTERM/SIGINT: drop fanotify (kernel auto-allows), shutdown D-Bus, exit

```rust
mod config;
mod decision;
mod dbus_interface;
mod event_log;
mod exclusions;
mod fanotify;
mod process_info;
mod rules;

use anyhow::Result;
use config::Config;
use decision::DecisionEngine;
use dbus_interface::FilesnitchInterface;
use exclusions::ExclusionList;
use process_info::ProcessInfoCache;
use rules::RuleStore;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Load config
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(Config::default_path);

    let config = if config_path.exists() {
        Config::load(&config_path)?
    } else {
        tracing::warn!("config not found at {}, using defaults", config_path.display());
        Config::default()
    };

    // 2. Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(
                    format!("filesnitchd={}", config.general.log_level).parse()?,
                ),
        )
        .init();

    tracing::info!(
        mode = ?config.general.operation_mode,
        protection = ?config.general.protection_mode,
        "filesnitchd starting"
    );

    // 3. Ensure DB directory exists
    if let Some(parent) = config.general.db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // 4. Create shared state
    let config = Arc::new(RwLock::new(config));
    let rules = Arc::new(RuleStore::new(
        &config.read().await.general.db_path,
    )?);
    let exclusions = Arc::new(RwLock::new(ExclusionList::new(&config.read().await)));
    let process_cache = Arc::new(ProcessInfoCache::new());

    // 5. Create decision engine
    let engine = Arc::new(DecisionEngine::new(
        config.clone(),
        rules.clone(),
        exclusions.clone(),
        process_cache.clone(),
    ));

    // 6. Initialize fanotify
    let (event_tx, mut event_rx) = mpsc::channel::<fanotify::FanotifyEvent>(256);

    let fan = match fanotify::init_fanotify() {
        Ok(fan) => {
            let _reader_handle = fanotify::spawn_event_reader(fan, event_tx);
            // We don't store `fan` here — the reader thread owns it.
            // Response writing will go through a separate channel.
            true
        }
        Err(e) => {
            tracing::error!("fanotify init failed: {} — running without monitoring", e);
            false
        }
    };

    // 7-8. Set up D-Bus
    let iface = FilesnitchInterface {
        engine: engine.clone(),
        config: config.clone(),
        rules: rules.clone(),
    };

    let conn = zbus::connection::Builder::system()?
        .name("org.filesnitch.Daemon")?
        .serve_at("/org/filesnitch/Daemon", iface)?
        .build()
        .await?;

    tracing::info!("D-Bus interface ready on org.filesnitch.Daemon");

    // 9. Notify systemd we're ready
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    // 10. Spawn watchdog task
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
        }
    });

    // 11. Spawn cleanup task
    let rules_cleanup = rules.clone();
    let cache_cleanup = process_cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            rules_cleanup.cleanup_expired().ok();
            cache_cleanup.cleanup();
        }
    });

    // 12. Main event loop
    let engine_loop = engine.clone();
    let signal_conn = conn.clone();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let request_id = event.request_id;
            let (allow, reason) = engine_loop.decide(&event).await;

            // Write fanotify response
            // (the actual response writing mechanism is set up in fanotify module)
            tracing::debug!(
                request_id,
                allow,
                reason = %reason,
                path = %event.target_path.display(),
                "decision made"
            );
        }
    });

    // 13. Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Stopping]);

    Ok(())
}
```

**Step 2: Verify it builds**

Run: `cargo build -p filesnitchd`
Expected: BUILD SUCCESS (may need adjustments for borrow checker issues)

**Step 3: Commit**

```bash
git add daemon/src/main.rs
git commit -m "feat(daemon): integrate all modules in main event loop"
```

---

## Phase 8: Shared Python D-Bus Client

### Task 13: Implement shared D-Bus client

**Files:**
- Modify: `shared/filesnitch_dbus/client.py`

**Step 1: Write the D-Bus client**

```python
"""D-Bus client proxy for filesnitchd."""

from dasbus.connection import SystemMessageBus
from dasbus.identifier import DBusServiceIdentifier

FILESNITCH_NAMESPACE = ("org", "filesnitch", "Daemon")

FILESNITCH = DBusServiceIdentifier(
    namespace=FILESNITCH_NAMESPACE,
    message_bus=SystemMessageBus(),
)


class FilesnitchClient:
    """Client for the filesnitchd D-Bus interface."""

    def __init__(self):
        self._proxy = FILESNITCH.get_proxy()

    @property
    def proxy(self):
        return self._proxy

    # --- Permission decisions ---

    def respond_to_request(self, request_id, action, duration, path_scope, permission):
        """Respond to a pending permission request."""
        self._proxy.RespondToRequest(request_id, action, duration, path_scope, permission)

    # --- Rules ---

    def list_rules(self, filter_dict=None):
        """List all rules."""
        return self._proxy.ListRules(filter_dict or {})

    def add_rule(self, rule_dict):
        """Add a new rule. Returns rule ID."""
        return self._proxy.AddRule(rule_dict)

    def delete_rule(self, rule_id):
        """Delete a rule by ID."""
        self._proxy.DeleteRule(rule_id)

    def export_rules(self):
        """Export rules as JSON string."""
        return self._proxy.ExportRules()

    def import_rules(self, json_str):
        """Import rules from JSON. Returns count imported."""
        return self._proxy.ImportRules(json_str)

    # --- Events ---

    def get_recent_events(self, count=50, filter_dict=None):
        """Get recent events."""
        return self._proxy.GetRecentEvents(count, filter_dict or {})

    # --- Config ---

    def get_config(self):
        """Get daemon configuration."""
        return self._proxy.GetConfig()

    def set_config(self, key, value):
        """Set a config value."""
        self._proxy.SetConfig(key, str(value))

    # --- Status ---

    def get_status(self):
        """Get daemon status."""
        return self._proxy.GetStatus()

    # --- Critical paths ---

    def get_critical_paths(self):
        """Get the critical paths list."""
        return self._proxy.GetCriticalPaths()

    def add_critical_path(self, path):
        """Add a critical path."""
        self._proxy.AddCriticalPath(path)

    def remove_critical_path(self, path):
        """Remove a critical path."""
        self._proxy.RemoveCriticalPath(path)

    # --- Signals ---

    def on_permission_request(self, callback):
        """Subscribe to PermissionRequest signals.

        callback(request_id, pid, executable, target_path, access_type, app_name, timestamp)
        """
        self._proxy.PermissionRequest.connect(callback)

    def on_rule_changed(self, callback):
        """Subscribe to RuleChanged signals.

        callback(rule_id, change_type)
        """
        self._proxy.RuleChanged.connect(callback)

    def on_event_logged(self, callback):
        """Subscribe to EventLogged signals.

        callback(event_dict)
        """
        self._proxy.EventLogged.connect(callback)
```

**Step 2: Commit**

```bash
git add shared/filesnitch_dbus/client.py
git commit -m "feat(shared): implement D-Bus client proxy with dasbus"
```

---

## Phase 9: CLI

### Task 14: Implement CLI main and subcommands

**Files:**
- Modify: `cli/filesnitch_cli/__main__.py`
- Create: `cli/filesnitch_cli/main.py`

**Step 1: Write main.py with click CLI**

```python
"""FileSnitch CLI - command line interface for filesnitchd."""

import json
import sys

import click
from rich.console import Console
from rich.table import Table

# Import will be: from filesnitch_dbus.client import FilesnitchClient
# For development, use relative path or sys.path manipulation


console = Console()


def get_client():
    """Get a D-Bus client, with error handling."""
    try:
        from filesnitch_dbus.client import FilesnitchClient
        return FilesnitchClient()
    except Exception as e:
        console.print(f"[red]Error connecting to filesnitchd:[/red] {e}")
        console.print("Is the daemon running? Try: systemctl start filesnitchd")
        sys.exit(1)


@click.group()
def cli():
    """FileSnitch - interactive file access firewall for your home directory."""
    pass


@cli.command()
def status():
    """Show daemon status."""
    client = get_client()
    status = client.get_status()
    config = client.get_config()

    table = Table(title="FileSnitch Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Operation Mode", str(status.get("operation_mode", "unknown")))
    table.add_row("Protection Mode", str(status.get("protection_mode", "unknown")))
    table.add_row("Pending Requests", str(status.get("pending_requests", 0)))
    table.add_row("Default Action", str(config.get("default_action", "unknown")))
    table.add_row("Prompt Timeout", f"{config.get('prompt_timeout', 30)}s")

    console.print(table)


@cli.group()
def rules():
    """Manage access rules."""
    pass


@rules.command("list")
@click.option("--app", default=None, help="Filter by application path")
@click.option("--path", default=None, help="Filter by target path")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def rules_list(app, path, json_output):
    """List all rules."""
    client = get_client()
    rule_list = client.list_rules()

    if json_output:
        click.echo(json.dumps(rule_list, indent=2, default=str))
        return

    table = Table(title="FileSnitch Rules")
    table.add_column("ID", style="dim")
    table.add_column("Application", style="cyan")
    table.add_column("Path", style="yellow")
    table.add_column("Permission")
    table.add_column("Action")
    table.add_column("Expires")
    table.add_column("Hits", justify="right")

    for rule in rule_list:
        action_style = "green" if rule.get("action") == "allow" else "red"
        table.add_row(
            str(rule.get("id", "")),
            str(rule.get("executable", "")),
            str(rule.get("path_pattern", "")),
            str(rule.get("permission", "")),
            f"[{action_style}]{rule.get('action', '')}[/{action_style}]",
            str(rule.get("expires_at", "never")),
            str(rule.get("hit_count", 0)),
        )

    console.print(table)


@rules.command("add")
@click.option("--app", required=True, help="Executable path")
@click.option("--path", required=True, help="Target path pattern")
@click.option("--permission", type=click.Choice(["read", "write", "readwrite"]), default="readwrite")
@click.option("--action", type=click.Choice(["allow", "deny"]), required=True)
@click.option("--duration", type=click.Choice(["forever", "1m", "10m", "60m", "12h"]), default="forever")
def rules_add(app, path, permission, action, duration):
    """Add a new rule."""
    client = get_client()
    rule_id = client.add_rule({
        "executable": app,
        "path_pattern": path,
        "permission": permission,
        "action": action,
        "duration": duration,
    })
    console.print(f"[green]Rule {rule_id} created.[/green]")


@rules.command("remove")
@click.argument("rule_id", type=int)
def rules_remove(rule_id):
    """Remove a rule by ID."""
    client = get_client()
    client.delete_rule(rule_id)
    console.print(f"[green]Rule {rule_id} deleted.[/green]")


@rules.command("export")
def rules_export():
    """Export rules as JSON."""
    client = get_client()
    click.echo(client.export_rules())


@rules.command("import")
@click.argument("file", type=click.File("r"), default="-")
def rules_import(file):
    """Import rules from JSON file (or stdin)."""
    client = get_client()
    data = file.read()
    count = client.import_rules(data)
    console.print(f"[green]Imported {count} rules.[/green]")


@cli.command()
@click.option("--follow", "-f", is_flag=True, help="Follow new events")
@click.option("--app", default=None, help="Filter by application")
@click.option("--path", default=None, help="Filter by path")
@click.option("--limit", "-n", default=50, help="Number of events to show")
def log(follow, app, path, limit):
    """Show the event log."""
    client = get_client()

    if not follow:
        events = client.get_recent_events(limit)
        table = Table(title="Recent Events")
        table.add_column("Time", style="dim")
        table.add_column("Application", style="cyan")
        table.add_column("Path", style="yellow")
        table.add_column("Access")
        table.add_column("Decision")
        table.add_column("Reason")

        for event in events:
            decision_style = "green" if event.get("decision") == "allow" else "red"
            table.add_row(
                str(event.get("timestamp", "")),
                str(event.get("executable", "")),
                str(event.get("target_path", "")),
                str(event.get("access_type", "")),
                f"[{decision_style}]{event.get('decision', '')}[/{decision_style}]",
                str(event.get("reason", "")),
            )

        console.print(table)
    else:
        # Follow mode: subscribe to EventLogged signals
        from dasbus.loop import EventLoop
        loop = EventLoop()

        def on_event(event):
            decision_style = "green" if event.get("decision") == "allow" else "red"
            console.print(
                f"[dim]{event.get('timestamp', '')}[/dim] "
                f"[cyan]{event.get('executable', '')}[/cyan] "
                f"[yellow]{event.get('target_path', '')}[/yellow] "
                f"{event.get('access_type', '')} "
                f"[{decision_style}]{event.get('decision', '')}[/{decision_style}]"
            )

        client.on_event_logged(on_event)
        console.print("[dim]Following event log (Ctrl+C to stop)...[/dim]")
        try:
            loop.run()
        except KeyboardInterrupt:
            pass


@cli.group()
def config():
    """View and change configuration."""
    pass


@config.command("get")
@click.argument("key", required=False)
def config_get(key):
    """Get configuration value(s)."""
    client = get_client()
    cfg = client.get_config()
    if key:
        if key in cfg:
            console.print(f"{key} = {cfg[key]}")
        else:
            console.print(f"[red]Unknown config key: {key}[/red]")
    else:
        for k, v in cfg.items():
            console.print(f"{k} = {v}")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a configuration value."""
    client = get_client()
    client.set_config(key, value)
    console.print(f"[green]{key} set to {value}[/green]")


def main():
    cli()
```

**Step 2: Update __main__.py**

```python
from filesnitch_cli.main import main

if __name__ == "__main__":
    main()
```

**Step 3: Commit**

```bash
git add cli/
git commit -m "feat(cli): implement all CLI commands with click and rich"
```

---

### Task 15: Implement CLI watch mode

**Files:**
- Create: `cli/filesnitch_cli/watch.py`
- Modify: `cli/filesnitch_cli/main.py` (add watch command)

**Step 1: Write watch.py**

```python
"""Interactive watch mode for FileSnitch CLI."""

import sys
import threading
from collections import OrderedDict

from rich.console import Console
from rich.live import Live
from rich.table import Table


console = Console()


class WatchMode:
    """Interactive mode showing pending permission requests."""

    def __init__(self, client):
        self.client = client
        self.pending = OrderedDict()  # request_id -> request_info
        self.lock = threading.Lock()

    def on_permission_request(self, request_id, pid, executable, target_path, access_type, app_name, timestamp):
        """Callback for incoming permission requests."""
        with self.lock:
            self.pending[request_id] = {
                "request_id": request_id,
                "pid": pid,
                "executable": executable,
                "target_path": target_path,
                "access_type": access_type,
                "app_name": app_name,
                "timestamp": timestamp,
            }

    def make_table(self):
        """Generate the current pending requests table."""
        table = Table(title="Pending Permission Requests")
        table.add_column("#", style="bold", width=4)
        table.add_column("Application", style="cyan")
        table.add_column("Path", style="yellow")
        table.add_column("Access")
        table.add_column("PID", justify="right")

        with self.lock:
            for idx, (req_id, req) in enumerate(self.pending.items(), 1):
                table.add_row(
                    str(idx),
                    f"{req['app_name']} ({req['executable']})",
                    req["target_path"],
                    req["access_type"].upper(),
                    str(req["pid"]),
                )

        return table

    def handle_input(self, user_input):
        """Parse user input and respond to a request.

        Formats:
          1a     -> allow request #1 once
          1d     -> deny request #1 once
          1af    -> allow request #1 forever
          1 allow once
          1 deny forever folder
        """
        parts = user_input.strip().split()
        if not parts:
            return

        # Parse shorthand
        first = parts[0]
        if len(first) >= 2 and first[0].isdigit():
            num_str = ""
            rest = ""
            for i, ch in enumerate(first):
                if ch.isdigit():
                    num_str += ch
                else:
                    rest = first[i:]
                    break

            idx = int(num_str)
            action = "allow" if rest.startswith("a") else "deny"
            duration = "forever" if "f" in rest else "once"
        elif len(parts) >= 2:
            idx = int(parts[0])
            action = parts[1]
            duration = parts[2] if len(parts) > 2 else "once"
        else:
            console.print("[red]Invalid input. Use: <#> <allow|deny> [duration][/red]")
            return

        with self.lock:
            keys = list(self.pending.keys())
            if idx < 1 or idx > len(keys):
                console.print(f"[red]No request #{idx}[/red]")
                return
            request_id = keys[idx - 1]
            req = self.pending.pop(request_id)

        try:
            self.client.respond_to_request(
                request_id,
                action,
                duration,
                "exact",    # default scope
                "readwrite",  # default permission
            )
            style = "green" if action == "allow" else "red"
            console.print(
                f"[{style}]{action.upper()}[/{style}] "
                f"{req['app_name']} -> {req['target_path']} ({duration})"
            )
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def run(self):
        """Run the interactive watch mode."""
        from dasbus.loop import EventLoop
        import gi
        gi.require_version("GLib", "2.0")
        from gi.repository import GLib

        self.client.on_permission_request(self.on_permission_request)

        console.print("[bold]FileSnitch Watch Mode[/bold]")
        console.print("Commands: <#>a (allow once), <#>d (deny once), <#>af (allow forever)")
        console.print("          <#> allow|deny once|1m|10m|60m|12h|forever")
        console.print("Press Ctrl+C to exit.\n")

        # Run GLib main loop in background for D-Bus signals
        loop = GLib.MainLoop()
        loop_thread = threading.Thread(target=loop.run, daemon=True)
        loop_thread.start()

        try:
            with Live(self.make_table(), refresh_per_second=2, console=console) as live:
                while True:
                    live.update(self.make_table())
                    try:
                        user_input = console.input("[bold]> [/bold]")
                        self.handle_input(user_input)
                    except EOFError:
                        break
        except KeyboardInterrupt:
            pass
        finally:
            loop.quit()
            console.print("\n[dim]Watch mode ended.[/dim]")
```

**Step 2: Add watch command to main.py**

Add to `main.py`:
```python
@cli.command()
def watch():
    """Interactive mode - approve/deny file access requests in real time."""
    client = get_client()
    from filesnitch_cli.watch import WatchMode
    watcher = WatchMode(client)
    watcher.run()
```

**Step 3: Commit**

```bash
git add cli/
git commit -m "feat(cli): add interactive watch mode with live-updating table"
```

---

## Phase 10: GUI - Permission Prompt

### Task 16: Implement GTK4 application skeleton

**Files:**
- Modify: `ui/filesnitch_ui/__main__.py`
- Create: `ui/filesnitch_ui/app.py`
- Create: `ui/filesnitch_ui/dbus_client.py`

**Step 1: Write app.py**

```python
"""Main GTK4 application for FileSnitch."""

import sys
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib

from filesnitch_ui.dbus_client import get_client


class FilesnitchApp(Adw.Application):
    """Main FileSnitch GTK4 application."""

    def __init__(self):
        super().__init__(
            application_id="org.filesnitch.UI",
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        self.client = None
        self.main_window = None

    def do_activate(self):
        self.client = get_client()

        # Subscribe to permission request signals
        self.client.on_permission_request(self._on_permission_request)

        # Show main window if no windows exist
        if not self.get_active_window():
            from filesnitch_ui.main_window import MainWindow
            self.main_window = MainWindow(application=self)
            self.main_window.present()

    def _on_permission_request(self, request_id, pid, executable, target_path, access_type, app_name, timestamp):
        """Handle incoming permission request signal."""
        GLib.idle_add(
            self._show_prompt,
            request_id, pid, executable, target_path, access_type, app_name, timestamp,
        )

    def _show_prompt(self, request_id, pid, executable, target_path, access_type, app_name, timestamp):
        """Show the permission prompt popup on the main thread."""
        from filesnitch_ui.prompt_window import PromptWindow
        prompt = PromptWindow(
            application=self,
            client=self.client,
            request_id=request_id,
            pid=pid,
            executable=executable,
            target_path=target_path,
            access_type=access_type,
            app_name=app_name,
        )
        prompt.present()
        return GLib.SOURCE_REMOVE
```

**Step 2: Write dbus_client.py (thin wrapper)**

```python
"""D-Bus client for the UI - wraps shared client."""

import sys
import os

# Add shared package to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))

from filesnitch_dbus.client import FilesnitchClient


def get_client():
    return FilesnitchClient()
```

**Step 3: Update __main__.py**

```python
"""Entry point for filesnitch-ui."""

from filesnitch_ui.app import FilesnitchApp


def main():
    app = FilesnitchApp()
    app.run()


if __name__ == "__main__":
    main()
```

**Step 4: Commit**

```bash
git add ui/
git commit -m "feat(ui): create GTK4 application skeleton with D-Bus signal subscription"
```

---

### Task 17: Implement permission prompt window

**Files:**
- Create: `ui/filesnitch_ui/prompt_window.py`

**Step 1: Write prompt_window.py**

This is the OpenSnitch-style popup. Uses Adw.Window with:
- App icon, name, executable path, PID display
- Action radio buttons (Allow/Deny)
- Duration dropdown
- Path scope radio buttons
- Permission radio buttons
- Countdown timer label
- Apply button

```python
"""Permission prompt popup window."""

import os
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib, Gdk


class PromptWindow(Adw.Window):
    """Permission request popup dialog."""

    DURATIONS = [
        ("This time only", "once"),
        ("1 minute", "1m"),
        ("10 minutes", "10m"),
        ("60 minutes", "60m"),
        ("12 hours", "12h"),
        ("Forever", "forever"),
    ]

    def __init__(self, application, client, request_id, pid, executable,
                 target_path, access_type, app_name, timeout=30):
        super().__init__(
            title="FileSnitch - Permission Request",
            default_width=500,
            default_height=480,
            modal=True,
        )

        self.client = client
        self.request_id = request_id
        self.remaining = timeout
        self.responded = False

        # Keep above other windows
        self.set_deletable(False)

        # Main content
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(20)
        content.set_margin_bottom(20)
        content.set_margin_start(20)
        content.set_margin_end(20)

        # Header with icon and app info
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        icon = self._get_app_icon(executable)
        header.append(icon)

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        name_label = Gtk.Label(label=app_name or os.path.basename(executable))
        name_label.add_css_class("title-2")
        name_label.set_halign(Gtk.Align.START)
        info_box.append(name_label)

        path_label = Gtk.Label(label=executable)
        path_label.add_css_class("dim-label")
        path_label.set_halign(Gtk.Align.START)
        path_label.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        info_box.append(path_label)

        pid_label = Gtk.Label(label=f"PID {pid}")
        pid_label.add_css_class("dim-label")
        pid_label.set_halign(Gtk.Align.START)
        info_box.append(pid_label)

        header.append(info_box)
        content.append(header)

        # Access description
        access_label = Gtk.Label(
            label=f"wants to {access_type.upper()}:",
        )
        access_label.add_css_class("title-3")
        access_label.set_halign(Gtk.Align.START)
        content.append(access_label)

        target_label = Gtk.Label(label=target_path)
        target_label.set_selectable(True)
        target_label.set_halign(Gtk.Align.START)
        target_label.add_css_class("monospace")
        content.append(target_label)

        content.append(Gtk.Separator())

        # Action: Allow / Deny
        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        action_label = Gtk.Label(label="Action:")
        action_label.set_halign(Gtk.Align.START)
        action_box.append(action_label)

        self.allow_check = Gtk.CheckButton(label="Allow")
        self.deny_check = Gtk.CheckButton(label="Deny")
        self.deny_check.set_group(self.allow_check)
        self.deny_check.set_active(True)
        action_box.append(self.allow_check)
        action_box.append(self.deny_check)
        content.append(action_box)

        # Duration dropdown
        duration_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        duration_label = Gtk.Label(label="Duration:")
        duration_label.set_halign(Gtk.Align.START)
        duration_box.append(duration_label)

        self.duration_dropdown = Gtk.DropDown.new_from_strings(
            [d[0] for d in self.DURATIONS]
        )
        self.duration_dropdown.set_selected(0)
        duration_box.append(self.duration_dropdown)
        content.append(duration_box)

        # Path scope
        scope_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        scope_title = Gtk.Label(label="Apply to:")
        scope_title.set_halign(Gtk.Align.START)
        scope_box.append(scope_title)

        self.scope_exact = Gtk.CheckButton(label=f"This exact file ({os.path.basename(target_path)})")
        scope_box.append(self.scope_exact)

        parent_dir = os.path.dirname(target_path)
        self.scope_folder = Gtk.CheckButton(label=f"This folder ({parent_dir}/*)")
        self.scope_folder.set_group(self.scope_exact)
        self.scope_folder.set_active(True)
        scope_box.append(self.scope_folder)

        self.scope_recursive = Gtk.CheckButton(label=f"Folder + subfolders ({parent_dir}/**)")
        self.scope_recursive.set_group(self.scope_exact)
        scope_box.append(self.scope_recursive)

        self.scope_home = Gtk.CheckButton(label="Entire home directory")
        self.scope_home.set_group(self.scope_exact)
        scope_box.append(self.scope_home)

        custom_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.scope_custom = Gtk.CheckButton(label="Custom:")
        self.scope_custom.set_group(self.scope_exact)
        custom_box.append(self.scope_custom)
        self.scope_custom_entry = Gtk.Entry()
        self.scope_custom_entry.set_hexpand(True)
        self.scope_custom_entry.set_text(parent_dir + "/*")
        custom_box.append(self.scope_custom_entry)
        scope_box.append(custom_box)

        content.append(scope_box)

        # Permission type
        perm_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        perm_label = Gtk.Label(label="Permission:")
        perm_box.append(perm_label)

        self.perm_read = Gtk.CheckButton(label="Read only")
        self.perm_write = Gtk.CheckButton(label="Write only")
        self.perm_write.set_group(self.perm_read)
        self.perm_rw = Gtk.CheckButton(label="Read & Write")
        self.perm_rw.set_group(self.perm_read)

        if access_type == "read":
            self.perm_read.set_active(True)
        else:
            self.perm_rw.set_active(True)

        perm_box.append(self.perm_read)
        perm_box.append(self.perm_write)
        perm_box.append(self.perm_rw)
        content.append(perm_box)

        content.append(Gtk.Separator())

        # Bottom bar: Apply button + timer
        bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        self.apply_button = Gtk.Button(label="Apply")
        self.apply_button.add_css_class("suggested-action")
        self.apply_button.connect("clicked", self._on_apply)
        bottom.append(self.apply_button)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        bottom.append(spacer)

        self.timer_label = Gtk.Label(label=f"Timeout: {self.remaining}s")
        self.timer_label.add_css_class("dim-label")
        bottom.append(self.timer_label)

        content.append(bottom)
        self.set_content(content)

        # Start countdown
        self._timer_id = GLib.timeout_add_seconds(1, self._tick)

    def _get_app_icon(self, executable):
        """Try to find an icon for the application."""
        icon = Gtk.Image.new_from_icon_name("application-x-executable")
        icon.set_pixel_size(48)

        # Try to find a desktop file for better icon
        app_name = os.path.basename(executable)
        app_info = Gio.DesktopAppInfo.new(f"{app_name}.desktop")
        if app_info:
            gicon = app_info.get_icon()
            if gicon:
                icon.set_from_gicon(gicon)

        return icon

    def _tick(self):
        """Countdown timer tick."""
        self.remaining -= 1
        self.timer_label.set_label(f"Timeout: {self.remaining}s")

        if self.remaining <= 0:
            self._auto_deny()
            return GLib.SOURCE_REMOVE

        return GLib.SOURCE_CONTINUE

    def _auto_deny(self):
        """Auto-deny on timeout."""
        if not self.responded:
            self.responded = True
            try:
                self.client.respond_to_request(
                    self.request_id, "deny", "once", "exact", "readwrite"
                )
            except Exception:
                pass
            self.close()

    def _on_apply(self, button):
        """Handle the Apply button click."""
        if self.responded:
            return
        self.responded = True

        if self._timer_id:
            GLib.source_remove(self._timer_id)

        action = "allow" if self.allow_check.get_active() else "deny"
        duration = self.DURATIONS[self.duration_dropdown.get_selected()][1]

        if self.scope_exact.get_active():
            scope = "exact"
        elif self.scope_folder.get_active():
            scope = "folder"
        elif self.scope_recursive.get_active():
            scope = "recursive"
        elif self.scope_home.get_active():
            scope = "home"
        else:
            scope = self.scope_custom_entry.get_text()

        if self.perm_read.get_active():
            permission = "read"
        elif self.perm_write.get_active():
            permission = "write"
        else:
            permission = "readwrite"

        try:
            self.client.respond_to_request(
                self.request_id, action, duration, scope, permission
            )
        except Exception as e:
            print(f"Error responding: {e}")

        self.close()
```

**Step 2: Commit**

```bash
git add ui/filesnitch_ui/prompt_window.py
git commit -m "feat(ui): implement OpenSnitch-style permission prompt popup"
```

---

## Phase 11: GUI - Main Window

### Task 18: Implement main window with tabs

**Files:**
- Create: `ui/filesnitch_ui/main_window.py`
- Create: `ui/filesnitch_ui/rules_page.py`
- Create: `ui/filesnitch_ui/log_page.py`
- Create: `ui/filesnitch_ui/settings_page.py`

**Step 1: Write main_window.py**

The main window uses Adw.ApplicationWindow with a Gtk.Notebook for three tabs: Rules, Event Log, Settings. Each tab is a separate widget class. The window connects to D-Bus signals for live updates.

Key structure:
```python
class MainWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_default_size(900, 600)
        self.set_title("FileSnitch")

        # Create header bar
        header = Adw.HeaderBar()

        # Create notebook with 3 tabs
        notebook = Gtk.Notebook()
        notebook.append_page(RulesPage(self), Gtk.Label(label="Rules"))
        notebook.append_page(LogPage(self), Gtk.Label(label="Event Log"))
        notebook.append_page(SettingsPage(self), Gtk.Label(label="Settings"))

        # Layout
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.append(header)
        box.append(notebook)
        self.set_content(box)
```

**Step 2: Write rules_page.py**

Uses Gtk.ColumnView with Gio.ListStore and Gtk.SortListModel for the sortable rules table. Columns: Application, Path, Permission, Action, Duration, Hits, Status. Includes a search entry for filtering, and buttons for Add/Edit/Delete.

**Step 3: Write log_page.py**

Uses Gtk.ListView with Gio.ListStore for the scrolling event log. Subscribes to EventLogged D-Bus signal for live updates. Filter bar with text entries for app and path filtering.

**Step 4: Write settings_page.py**

Uses Adw.PreferencesPage with Adw.PreferencesGroup sections:
- Protection mode: Adw.SwitchRow toggling critical-only vs everything
- Operation mode: Adw.SwitchRow toggling learning vs enforce
- Critical files: Gtk.ListBox with add/remove buttons
- Default action: Adw.ComboRow (Allow/Deny)
- Prompt timeout: Adw.SpinRow (10-120)
- Excluded applications: Gtk.ListBox with add/remove
- Log level: Adw.ComboRow

All changes call the D-Bus SetConfig method immediately.

**Step 5: Commit**

```bash
git add ui/filesnitch_ui/
git commit -m "feat(ui): implement main window with rules, event log, and settings tabs"
```

---

### Task 19: Implement system tray

**Files:**
- Create: `ui/filesnitch_ui/tray.py`

**Step 1: Write tray.py**

Uses the StatusNotifierItem protocol via Gio.DBusProxy or libappindicator3 if available. Provides a context menu with:
- "Open FileSnitch" — shows/raises main window
- Protection mode toggle
- Operation mode toggle
- "Pause (5 min)"
- Separator
- "Quit"

If libappindicator3 is not available, falls back to just running without a tray icon.

**Step 2: Commit**

```bash
git add ui/filesnitch_ui/tray.py
git commit -m "feat(ui): add system tray icon with StatusNotifierItem"
```

---

## Phase 12: Nix Packaging

### Task 20: Create flake.nix with packages and NixOS module

**Files:**
- Create: `flake.nix`
- Create: `nix/daemon.nix`
- Create: `nix/ui.nix`
- Create: `nix/cli.nix`
- Create: `nix/module.nix`

**Step 1: Write flake.nix**

```nix
{
  description = "FileSnitch - interactive file access firewall for Linux home directories";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;
      in
      {
        packages = {
          filesnitchd = pkgs.callPackage ./nix/daemon.nix { inherit craneLib; };
          filesnitch-ui = pkgs.callPackage ./nix/ui.nix { };
          filesnitch-cli = pkgs.callPackage ./nix/cli.nix { };
          default = self.packages.${system}.filesnitchd;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo rustc rust-analyzer clippy rustfmt
            pkg-config dbus openssl sqlite
            python3 python3Packages.pygobject3
            python3Packages.dasbus python3Packages.click
            python3Packages.rich
            gtk4 libadwaita gobject-introspection
          ];
        };
      }
    ) // {
      nixosModules.default = import ./nix/module.nix self;
    };
}
```

**Step 2: Write nix/daemon.nix**

Builds the Rust daemon using crane. Key: vendor dependencies, link against dbus and sqlite.

**Step 3: Write nix/ui.nix**

Python application wrapped with `wrapGAppsHook4` for GTK4 introspection.

**Step 4: Write nix/cli.nix**

Python application with click/rich/dasbus.

**Step 5: Write nix/module.nix**

NixOS module providing:
- `services.filesnitch.enable`
- `services.filesnitch.protectionMode`
- `services.filesnitch.operationMode`
- `services.filesnitch.defaultAction`
- `services.filesnitch.promptTimeout`
- `services.filesnitch.excludedExecutables`
- Installs D-Bus policy via `services.dbus.packages`
- Creates systemd service (Type=dbus, BusName=org.filesnitch.Daemon)
- Creates `/var/lib/filesnitchd` state directory

**Step 6: Verify flake builds**

Run: `nix build .#filesnitchd`
Expected: BUILD SUCCESS

**Step 7: Commit**

```bash
git add flake.nix flake.lock nix/
git commit -m "feat(nix): add flake with packages and NixOS module"
```

---

## Phase 13: Integration and Testing

### Task 21: Integration testing

**Step 1: Test daemon starts and connects to D-Bus**

Run (as root or in VM): `sudo cargo run -p filesnitchd -- config/filesnitchd.toml`
Verify: daemon logs "filesnitchd starting" and "D-Bus interface ready"

**Step 2: Test CLI can connect**

Run: `filesnitch status`
Verify: shows daemon status

**Step 3: Test fanotify monitoring**

In learning mode, touch a file in /home and verify the event log shows it.

**Step 4: Test rule creation and matching**

Add a rule via CLI, trigger an access that matches, verify it's auto-handled.

**Step 5: Test prompt popup**

Switch to enforce mode, access a critical file, verify the GTK4 popup appears.

**Step 6: Test timeout behavior**

Let a prompt time out, verify the default action (deny) is applied.

**Step 7: Commit any fixes**

```bash
git add -A
git commit -m "fix: integration test fixes"
```

---

### Task 22: Final polish and .gitignore update

**Files:**
- Modify: `.gitignore`

**Step 1: Update .gitignore**

```
/target
/.direnv
__pycache__/
*.pyc
*.egg-info/
/result
```

**Step 2: Final commit**

```bash
git add .gitignore
git commit -m "chore: update gitignore for Python and Nix artifacts"
```
