use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};
use tokio::sync::mpsc;

/// Counter for assigning unique request IDs to permission events.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum number of events waiting for a decision concurrently.
/// Beyond this, new events are auto-allowed to prevent resource exhaustion.
const MAX_PENDING: usize = 512;

/// How long a pending event can wait before being auto-allowed.
/// This is a safety net — the decision engine has its own prompt timeout.
/// Kept short (10s) so blocked processes don't freeze the system for long.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// UID threshold for system processes. Processes with UID below this
/// are auto-allowed in the reader thread without hitting the async pipeline.
const SYSTEM_UID_THRESHOLD: u32 = 1000;

/// A fanotify permission event to be decided on.
#[derive(Debug)]
pub struct FanotifyEvent {
    pub request_id: u64,
    pub pid: i32,
    pub target_path: PathBuf,
    pub access_type: AccessType,
}

/// The type of file access being requested.
#[derive(Debug, Clone, Copy)]
pub enum AccessType {
    Read,
    Write,
}

/// A duped fd waiting for a decision response.
struct PendingFd {
    duped_fd: i32,
    created_at: Instant,
}

/// Initialize fanotify with permission-based interception on `/home`.
pub fn init_fanotify() -> Result<Fanotify> {
    let fan = Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_CONTENT,
        EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC,
    )
    .context("failed to init fanotify (need CAP_SYS_ADMIN)")?;

    fan.mark(
        MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
        MaskFlags::FAN_OPEN_PERM,
        None::<std::os::unix::io::RawFd>,
        Some("/home"),
    )
    .context("failed to mark /home mount for fanotify")?;

    tracing::info!("fanotify initialized, watching /home mount for open permission events");
    Ok(fan)
}

/// Spawn the fanotify event processing pipeline.
///
/// Creates three threads:
/// - **reader**: reads fanotify events, dups fds, sends events to the
///   decision engine without blocking. Events from the daemon's own PID,
///   system processes (UID < 1000), and known excluded basenames are
///   auto-allowed immediately in the reader thread. In learning mode,
///   ALL events are auto-allowed without hitting the async pipeline.
/// - **responder**: receives decisions from the engine and writes fanotify
///   responses using the duped fds.
/// - **timeout monitor**: periodically checks for stale pending events
///   and auto-allows them to prevent system freezes.
///
/// This design ensures the reader never blocks on decisions, so new
/// file access events are always processed promptly.
pub fn spawn_event_reader(
    fan: Fanotify,
    event_tx: mpsc::Sender<FanotifyEvent>,
    response_rx: std::sync::mpsc::Receiver<(u64, bool)>,
    learning_mode: Arc<AtomicBool>,
    exclusion_basenames: Arc<HashSet<String>>,
) -> JoinHandle<()> {
    let fan = Arc::new(fan);
    let pending_fds: Arc<Mutex<HashMap<u64, PendingFd>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let my_pid = std::process::id() as i32;

    // Spawn response writer thread.
    let fan_responder = fan.clone();
    let pending_responder = pending_fds.clone();
    thread::Builder::new()
        .name("fanotify-responder".into())
        .spawn(move || {
            response_writer_loop(&fan_responder, &pending_responder, &response_rx);
        })
        .expect("failed to spawn fanotify responder thread");

    // Spawn timeout monitor thread.
    let fan_timeout = fan.clone();
    let pending_timeout = pending_fds.clone();
    thread::Builder::new()
        .name("fanotify-timeout".into())
        .spawn(move || {
            timeout_monitor_loop(&fan_timeout, &pending_timeout);
        })
        .expect("failed to spawn fanotify timeout thread");

    // Spawn event reader thread (returned handle).
    thread::Builder::new()
        .name("fanotify-reader".into())
        .spawn(move || {
            tracing::info!("fanotify reader thread started");
            event_reader_loop(
                &fan,
                &event_tx,
                &pending_fds,
                my_pid,
                &learning_mode,
                &exclusion_basenames,
            );
            tracing::info!("fanotify reader thread exiting");
        })
        .expect("failed to spawn fanotify reader thread")
}

/// Main loop: reads fanotify events, dups fds, sends to decision engine.
/// Never blocks on responses — continues processing events immediately.
///
/// Pre-filters are ordered to minimize syscalls per event:
/// 1. Self-PID: auto-allow (no syscalls, deadlock prevention)
/// 2. Learning mode: auto-allow (no syscalls, just atomic load)
/// 3. System UID < 1000: auto-allow (1 procfs read)
/// 4. Known excluded basenames: auto-allow (1 procfs readlink)
/// 5. Path resolution + /home filter: auto-allow non-/home (1 readlink)
///
/// This ordering ensures cheap checks run first, so expensive path
/// resolution only happens for non-excluded user processes.
fn event_reader_loop(
    fan: &Fanotify,
    event_tx: &mpsc::Sender<FanotifyEvent>,
    pending_fds: &Mutex<HashMap<u64, PendingFd>>,
    my_pid: i32,
    learning_mode: &AtomicBool,
    exclusion_basenames: &HashSet<String>,
) {
    loop {
        let events = match fan.read_events() {
            Ok(events) => events,
            Err(nix::errno::Errno::EAGAIN) => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to read fanotify events");
                break;
            }
        };

        for event in &events {
            if !event.check_version() {
                tracing::warn!("fanotify event version mismatch, skipping");
                continue;
            }

            let fd = match event.fd() {
                Some(fd) => fd,
                None => {
                    tracing::debug!("fanotify overflow event, skipping");
                    continue;
                }
            };

            let pid = event.pid();

            // Self-exclusion: never intercept the daemon's own file access
            // to prevent deadlocks (e.g., accessing the SQLite database).
            if pid == my_pid {
                write_allow(fan, &fd);
                continue;
            }

            // Learning mode: auto-allow immediately. This is checked BEFORE
            // path resolution to avoid any syscalls in learning mode —
            // critical for surviving login bursts without freezing.
            if learning_mode.load(Ordering::Relaxed) {
                write_allow(fan, &fd);
                continue;
            }

            // Quick UID check: system processes (UID < 1000) are auto-allowed
            // without path resolution. Catches daemons like dbus-daemon,
            // polkitd, etc. One procfs read is cheaper than blocking them.
            if let Some(uid) = quick_uid(pid) {
                if uid < SYSTEM_UID_THRESHOLD {
                    write_allow(fan, &fd);
                    continue;
                }
            }

            // Quick basename exclusion: check the process executable basename
            // against the known exclusion set. Catches desktop processes
            // (gnome-shell, sway, etc.) without path resolution.
            if let Some(basename) = quick_exe_basename(pid) {
                if exclusion_basenames.contains(&basename) {
                    write_allow(fan, &fd);
                    continue;
                }
            }

            // Resolve the file path from the event fd.
            let target_path = match resolve_event_path(&fd) {
                Ok(path) => path,
                Err(e) => {
                    tracing::debug!(
                        pid,
                        error = %e,
                        "failed to resolve event fd path, auto-allowing"
                    );
                    write_allow(fan, &fd);
                    continue;
                }
            };

            // Quick path filter: auto-allow anything not under /home.
            if !target_path.starts_with("/home/") {
                write_allow(fan, &fd);
                continue;
            }

            // Check if we're at capacity — auto-allow to prevent resource exhaustion.
            {
                let map = pending_fds.lock().expect("pending_fds lock poisoned");
                if map.len() >= MAX_PENDING {
                    tracing::warn!(
                        pid,
                        path = %target_path.display(),
                        pending = map.len(),
                        "too many pending events, auto-allowing"
                    );
                    drop(map);
                    write_allow(fan, &fd);
                    continue;
                }
            }

            // We only monitor FAN_OPEN_PERM, so all events are opens.
            // Treat them as reads since we can't determine write intent
            // from the open permission event alone.
            let access_type = AccessType::Read;

            let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

            // Dup the event fd so it survives after the event is dropped.
            // The kernel matches fanotify responses by the underlying file,
            // so a duped fd works for responding later.
            let raw_fd = fd.as_raw_fd();
            let duped = unsafe { libc::dup(raw_fd) };
            if duped < 0 {
                tracing::error!(pid, "failed to dup event fd, auto-allowing");
                write_allow(fan, &fd);
                continue;
            }

            // Store the duped fd for later response.
            {
                let mut map = pending_fds.lock().expect("pending_fds lock poisoned");
                map.insert(
                    request_id,
                    PendingFd {
                        duped_fd: duped,
                        created_at: Instant::now(),
                    },
                );
            }

            let event_info = FanotifyEvent {
                request_id,
                pid,
                target_path,
                access_type,
            };

            tracing::debug!(
                request_id,
                pid,
                path = %event_info.target_path.display(),
                access = ?event_info.access_type,
                "fanotify permission event"
            );

            // Send to the decision engine. Use try_send to never block
            // the reader — if the channel is full, auto-allow.
            if let Err(e) = event_tx.try_send(event_info) {
                tracing::warn!(
                    request_id,
                    error = %e,
                    "decision channel full or closed, auto-allowing"
                );
                let mut map = pending_fds.lock().expect("pending_fds lock poisoned");
                if let Some(pfd) = map.remove(&request_id) {
                    respond_duped(fan, pfd.duped_fd, true);
                }
            }
            // NOTE: We do NOT wait for a response here.
            // The responder thread handles decisions asynchronously.
        }
    }
}

/// Receives decisions from the engine and writes fanotify responses.
fn response_writer_loop(
    fan: &Fanotify,
    pending_fds: &Mutex<HashMap<u64, PendingFd>>,
    response_rx: &std::sync::mpsc::Receiver<(u64, bool)>,
) {
    tracing::info!("fanotify response writer started");

    while let Ok((request_id, allowed)) = response_rx.recv() {
        let mut map = pending_fds.lock().expect("pending_fds lock poisoned");
        if let Some(pfd) = map.remove(&request_id) {
            drop(map);
            respond_duped(fan, pfd.duped_fd, allowed);
            tracing::debug!(
                request_id,
                allowed,
                "wrote fanotify response"
            );
        } else {
            tracing::debug!(
                request_id,
                "response for unknown request (already timed out?)"
            );
        }
    }

    tracing::info!("fanotify response writer exiting");
}

/// Periodically checks for stale pending events and auto-allows them.
fn timeout_monitor_loop(
    fan: &Fanotify,
    pending_fds: &Mutex<HashMap<u64, PendingFd>>,
) {
    tracing::info!("fanotify timeout monitor started");

    loop {
        thread::sleep(Duration::from_secs(2));

        // Collect expired entries while holding the lock, then release
        // the lock BEFORE writing responses. This prevents the reader
        // thread from being blocked by slow response writes.
        let expired: Vec<(u64, PendingFd)> = {
            let mut map = pending_fds.lock().expect("pending_fds lock poisoned");
            let expired_ids: Vec<u64> = map
                .iter()
                .filter(|(_, pfd)| pfd.created_at.elapsed() > RESPONSE_TIMEOUT)
                .map(|(id, _)| *id)
                .collect();

            expired_ids
                .into_iter()
                .filter_map(|id| map.remove(&id).map(|pfd| (id, pfd)))
                .collect()
        };

        for (id, pfd) in &expired {
            tracing::warn!(
                request_id = id,
                elapsed_secs = pfd.created_at.elapsed().as_secs(),
                "pending event timed out, auto-allowing"
            );
            respond_duped(fan, pfd.duped_fd, true);
        }
    }
}

/// Resolve the filesystem path from a fanotify event fd.
fn resolve_event_path(fd: &impl AsRawFd) -> Result<PathBuf> {
    let raw_fd = fd.as_raw_fd();
    let link = format!("/proc/self/fd/{raw_fd}");
    std::fs::read_link(&link).with_context(|| format!("failed to readlink {link}"))
}

/// Write an allow response for an event fd (used for immediate decisions).
fn write_allow(fan: &Fanotify, fd: &impl AsRawFd) {
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) };
    let response = FanotifyResponse::new(borrowed, Response::FAN_ALLOW);
    if let Err(e) = fan.write_response(response) {
        tracing::error!(error = %e, "failed to write fanotify allow response");
    }
}

/// Quick UID lookup from /proc/<pid>/status without full ProcessInfo resolution.
/// Returns None if the process is gone or the file can't be read.
fn quick_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|val| val.parse::<u32>().ok())
}

/// Quick executable basename lookup from /proc/<pid>/exe.
/// Returns None if the process is gone or the symlink can't be read.
fn quick_exe_basename(pid: i32) -> Option<String> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    exe.file_name()?.to_str().map(|s| s.to_string())
}

/// Write a response using a duped fd, then close it.
fn respond_duped(fan: &Fanotify, duped_fd: i32, allow: bool) {
    let response_flag = if allow {
        Response::FAN_ALLOW
    } else {
        Response::FAN_DENY
    };
    let borrowed = unsafe { BorrowedFd::borrow_raw(duped_fd) };
    let fan_response = FanotifyResponse::new(borrowed, response_flag);
    if let Err(e) = fan.write_response(fan_response) {
        tracing::error!(
            duped_fd,
            error = %e,
            "failed to write fanotify response for duped fd"
        );
    }
    unsafe {
        libc::close(duped_fd);
    }
}
