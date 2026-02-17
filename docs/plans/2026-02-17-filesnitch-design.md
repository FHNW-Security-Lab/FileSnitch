# FileSnitch Design Document

An interactive file access firewall for Linux home directories using fanotify permission events.

## Architecture

Three components communicating over D-Bus (system bus):

1. **filesnitchd** (Rust) -- system daemon running as root, fanotify interception, rule enforcement
2. **filesnitch-ui** (Python/GTK4) -- graphical popup prompts and settings/rule management
3. **filesnitch-cli** (Python) -- terminal-based rule management and interactive watch mode

## Daemon (filesnitchd)

### Runtime

Tokio async runtime. Dedicated std::thread for blocking fanotify reads. Events flow through `tokio::sync::mpsc` channels to the async decision engine. zbus handles D-Bus on the Tokio runtime.

### Fanotify Setup

- `fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY)`
- Single filesystem mark: `fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_PERM | FAN_ACCESS_PERM, AT_FDCWD, "/home")`
- Only /home is monitored. System directories are never affected.

### Decision Flow

1. Receive fanotify event, resolve process info from /proc
2. Check built-in exclusion list (system processes, UID < 1000, system.slice cgroup) -- auto-allow
3. Check protection mode:
   - Critical-only: if path not in critical files list, auto-allow
   - Protect-everything: proceed to rule check
4. Check rule database (in-memory cache first, SQLite fallback)
5. If matching non-expired rule found: apply it
6. If no match: emit `PermissionRequest` D-Bus signal, start timeout
7. Wait for `RespondToRequest` D-Bus call or timeout
8. Respond to fanotify with FAN_ALLOW or FAN_DENY
9. Persist rule if duration > "once", log event

### Process Identification

- `/proc/<pid>/exe` for executable path
- `/proc/<pid>/cmdline` for display name
- `/proc/<pid>/status` for UID/GID
- `/proc/self/fd/<event_fd>` readlink for target file path
- PID-to-exe cache (process can't change exe while alive)

### Learning Mode

All accesses auto-allowed but fully logged. Decision engine skips prompt step, always responds FAN_ALLOW. User reviews log to build baseline rules before switching to enforce mode.

### Signal Handling & Shutdown

- SIGTERM, SIGINT: close fanotify fd (kernel auto-allows pending), flush D-Bus, close SQLite
- Systemd WatchdogSec=30, daemon sends WATCHDOG=1 every 10s
- D-Bus service activation (lazy start on first client call)

## D-Bus Interface

Bus: `org.filesnitch.Daemon` on system bus.
Object: `/org/filesnitch/Daemon`
Interface: `org.filesnitch.Daemon`

### Methods

- `RespondToRequest(request_id: u64, action: s, duration: s, path_scope: s, permission: s)`
- `ListRules(filter: a{sv}) -> a(a{sv})`
- `AddRule(rule: a{sv}) -> u64`
- `EditRule(rule_id: u64, changes: a{sv})`
- `DeleteRule(rule_id: u64)`
- `ExportRules() -> s` (JSON)
- `ImportRules(json: s) -> u32`
- `GetRecentEvents(count: u32, filter: a{sv}) -> a(a{sv})`
- `GetConfig() -> a{sv}`
- `SetConfig(key: s, value: v)`
- `GetStatus() -> a{sv}`
- `GetCriticalPaths() -> as`
- `AddCriticalPath(path: s)`
- `RemoveCriticalPath(path: s)`

### Signals

- `PermissionRequest(request_id: u64, pid: u32, executable: s, target_path: s, access_type: s, app_name: s, timestamp: t)`
- `RuleChanged(rule_id: u64, change_type: s)`
- `EventLogged(event: a{sv})`
- `ConfigChanged(key: s, value: v)`

### D-Bus Policy

Root owns the bus name. All users can call methods and receive signals. D-Bus service activation file starts the daemon on demand.

## Rule Database

SQLite at `/var/lib/filesnitchd/rules.db`.

### Schema

```sql
CREATE TABLE rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    executable  TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    permission  TEXT NOT NULL,       -- "read" | "write" | "readwrite"
    action      TEXT NOT NULL,       -- "allow" | "deny"
    is_critical INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,                -- NULL = forever
    enabled     INTEGER NOT NULL DEFAULT 1,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    last_hit_at TEXT
);

CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    executable  TEXT NOT NULL,
    target_path TEXT NOT NULL,
    access_type TEXT NOT NULL,
    decision    TEXT NOT NULL,
    reason      TEXT NOT NULL,
    rule_id     INTEGER REFERENCES rules(id)
);

CREATE TABLE config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

### Rule Matching Priority

1. Critical-file rules (is_critical=1) checked first
2. Exact path > folder glob > recursive glob > home-wide
3. Deny takes priority over allow at same specificity

### Caching

Rules loaded into `HashMap<PathBuf, Vec<Rule>>` on startup. Kept in sync on writes. Expired rules lazily cleaned on access, periodically purged from SQLite.

## GUI (filesnitch-ui)

Python 3, GTK4 (PyGObject), libadwaita, dasbus for D-Bus.

### Permission Prompt

Modal window appearing on `PermissionRequest` signal. Shows: app icon + name, executable path, PID, target path, access type. User selects: action (allow/deny), duration (once/1m/10m/60m/12h/forever), path scope (exact/folder/recursive/home/custom), permission type (read/write/readwrite). Countdown timer visible, auto-denies on expiry. Window appears above all others.

### Main Window

Three tabs:
- **Rules**: sortable/searchable table, edit/delete/toggle, add button
- **Event Log**: live-scrolling feed with filtering
- **Settings**: protection mode, operation mode, critical files list, timeout config, excluded apps, log verbosity

### System Tray

StatusNotifierItem icon with menu: open window, toggle protection mode, toggle operation mode, pause 5 min, quit.

## CLI (filesnitch-cli)

Python 3, click, rich, shared D-Bus client from `filesnitch_dbus`.

### Commands

- `filesnitch watch` -- interactive USBGuard-style live prompt queue
- `filesnitch rules list|add|remove|edit|export|import`
- `filesnitch log [--follow]`
- `filesnitch status`
- `filesnitch config get|set`

## System Safety

### Built-in Exclusions (non-removable)

- All processes with UID < 1000
- All processes in system.slice cgroup
- Hardcoded list: init/systemd, shells, display servers, D-Bus, polkit, PAM/login/sudo, package managers, agents (gpg, ssh, keyring), audio servers, network managers, journald, cron, and FileSnitch's own processes
- User can extend but never shrink this list

### Failure Modes

- Daemon crash: fanotify fd closes, kernel auto-allows pending events, systemd restarts
- Daemon hang: WatchdogSec triggers restart
- D-Bus unavailable: apply default action, retry with backoff
- SQLite corruption: fall back to in-memory cache
- UI disconnected: wait for timeout, apply default action
- Prompt timeout: auto-deny (configurable)

### Protection Layers

1. Home directory protection (everything under /home)
2. Critical files protection (additional layer for sensitive paths)

Modes: "protect critical files only" (default) or "protect everything". Critical-file rules always override general rules.

### Default Critical Files

`.ssh`, `.gnupg`, `.bashrc`, `.zshrc`, `.profile`, `.bash_profile`, `.aws`, `.kube`, `.gitconfig`, `.config/git`, browser profile directories.

## Packaging

### Nix Flake

- `packages.filesnitchd` -- Rust daemon (crane/naersk)
- `packages.filesnitch-ui` -- Python GTK4 app (wrapGAppsHook4)
- `packages.filesnitch-cli` -- Python CLI (rich, click)
- `nixosModules.default` -- NixOS module with: enable, protectionMode, defaultAction, promptTimeout, excludedExecutables, operationMode
- D-Bus policy via `services.dbus.packages`
- Architectures: x86_64-linux, aarch64-linux

### Debian

cargo-deb for daemon. Separate .deb for Python packages.

### Project Structure

```
FileSnitch/
  Cargo.toml              # Workspace root
  flake.nix
  daemon/                  # Rust: main, fanotify, decision, dbus_interface, rules, config, exclusions, process_info, event_log
  ui/filesnitch_ui/        # Python GTK4: app, prompt_window, main_window, rules_page, log_page, settings_page, tray, dbus_client
  cli/filesnitch_cli/      # Python: main, watch, dbus_client
  shared/filesnitch_dbus/  # Shared D-Bus client
  dbus/                    # D-Bus policy + activation files
  systemd/                 # Systemd unit
  config/                  # Default TOML config
  nix/                     # Nix derivations + NixOS module
```

## Key Rust Dependencies

- `nix` (fanotify syscalls)
- `zbus` (D-Bus, async with Tokio)
- `tokio` (async runtime)
- `rusqlite` (SQLite)
- `toml` / `serde` (config)
- `tracing` (logging)
- `sd-notify` (systemd watchdog)

## Key Python Dependencies

- `PyGObject` (GTK4/libadwaita)
- `dasbus` (D-Bus)
- `click` (CLI)
- `rich` (terminal formatting)
