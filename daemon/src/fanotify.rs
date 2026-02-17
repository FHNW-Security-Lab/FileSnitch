use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};
use tokio::sync::mpsc;

/// Counter for assigning unique request IDs to permission events.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

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

/// Initialize fanotify with permission-based interception on `/home`.
///
/// Sets up a `FAN_CLASS_CONTENT` fanotify group that intercepts
/// `FAN_OPEN_PERM` and `FAN_ACCESS_PERM` events on the filesystem
/// containing `/home`. The caller must have `CAP_SYS_ADMIN`.
pub fn init_fanotify() -> Result<Fanotify> {
    let fan = Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_CONTENT,
        EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC,
    )
    .context("failed to init fanotify (need CAP_SYS_ADMIN)")?;

    fan.mark(
        MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
        MaskFlags::FAN_OPEN_PERM | MaskFlags::FAN_ACCESS_PERM,
        None::<std::os::unix::io::RawFd>,
        Some("/home"),
    )
    .context("failed to mark /home for fanotify")?;

    tracing::info!("fanotify initialized, watching /home filesystem for permission events");
    Ok(fan)
}

/// Spawn a blocking thread that reads fanotify permission events and
/// communicates with the async decision engine via channels.
///
/// The thread processes events one at a time:
///
/// 1. Read an event from fanotify (blocking).
/// 2. Resolve the file path from the event fd.
/// 3. Send the event to the async decision engine via `event_tx`.
/// 4. Wait for the allow/deny response on `response_rx`.
/// 5. Write the fanotify response back to the kernel.
///
/// If the decision channel is closed (engine shut down), events are
/// automatically allowed to prevent the system from hanging.
pub fn spawn_event_reader(
    fan: Fanotify,
    event_tx: mpsc::Sender<FanotifyEvent>,
    response_rx: std::sync::mpsc::Receiver<(u64, bool)>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("fanotify-reader".into())
        .spawn(move || {
            tracing::info!("fanotify reader thread started");
            event_reader_loop(&fan, &event_tx, &response_rx);
            tracing::info!("fanotify reader thread exiting");
        })
        .expect("failed to spawn fanotify reader thread")
}

/// Main loop for the fanotify reader thread.
fn event_reader_loop(
    fan: &Fanotify,
    event_tx: &mpsc::Sender<FanotifyEvent>,
    response_rx: &std::sync::mpsc::Receiver<(u64, bool)>,
) {
    loop {
        // Read a batch of events (blocks until at least one is available).
        let events = match fan.read_events() {
            Ok(events) => events,
            Err(nix::errno::Errno::EAGAIN) => {
                // Non-blocking mode returned no events; sleep briefly.
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to read fanotify events");
                break;
            }
        };

        for event in &events {
            // Verify the event metadata version matches what we expect.
            if !event.check_version() {
                tracing::warn!("fanotify event version mismatch, skipping");
                continue;
            }

            // Get the file descriptor for this event. None means overflow
            // (FAN_NOFD / queue overflow event) — skip it.
            let fd = match event.fd() {
                Some(fd) => fd,
                None => {
                    tracing::debug!("fanotify overflow event, skipping");
                    continue;
                }
            };

            let pid = event.pid();
            let mask = event.mask();

            // Resolve the actual file path from the event fd via /proc/self/fd.
            let target_path = match resolve_event_path(&fd) {
                Ok(path) => path,
                Err(e) => {
                    tracing::debug!(
                        pid,
                        error = %e,
                        "failed to resolve event fd path, auto-allowing"
                    );
                    auto_allow(fan, &fd);
                    continue;
                }
            };

            // Determine whether this is a read or write/open access.
            let access_type = if mask.contains(MaskFlags::FAN_ACCESS_PERM) {
                AccessType::Read
            } else {
                // FAN_OPEN_PERM — treat as write/open intent.
                AccessType::Write
            };

            let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

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

            // Send event to the async decision engine.
            // Use blocking_send since we are in a std thread.
            if event_tx.blocking_send(event_info).is_err() {
                // Decision engine channel closed — auto-allow to avoid hangs.
                tracing::warn!(
                    request_id,
                    "decision engine channel closed, auto-allowing"
                );
                auto_allow(fan, &fd);
                continue;
            }

            // Wait for the decision from the engine.
            let allow = match response_rx.recv() {
                Ok((resp_id, allowed)) => {
                    if resp_id != request_id {
                        tracing::error!(
                            expected = request_id,
                            got = resp_id,
                            "response request_id mismatch, auto-allowing"
                        );
                        true
                    } else {
                        allowed
                    }
                }
                Err(_) => {
                    // Response channel closed — auto-allow.
                    tracing::warn!(
                        request_id,
                        "response channel closed, auto-allowing"
                    );
                    true
                }
            };

            let response = if allow {
                Response::FAN_ALLOW
            } else {
                Response::FAN_DENY
            };

            let fan_response = FanotifyResponse::new(fd, response);
            if let Err(e) = fan.write_response(fan_response) {
                tracing::error!(
                    request_id,
                    error = %e,
                    "failed to write fanotify response"
                );
            }
        }
    }
}

/// Resolve the filesystem path that a fanotify event fd points to.
///
/// Uses `/proc/self/fd/<raw_fd>` readlink to determine the actual path.
fn resolve_event_path(fd: &impl AsRawFd) -> Result<PathBuf> {
    let raw_fd = fd.as_raw_fd();
    let link = format!("/proc/self/fd/{raw_fd}");
    std::fs::read_link(&link).with_context(|| format!("failed to readlink {link}"))
}

/// Send an auto-allow response for an event fd.
///
/// Used when we cannot process the event normally (e.g., channel closed,
/// path resolution failed) to prevent the kernel from blocking the
/// process indefinitely.
fn auto_allow(fan: &Fanotify, fd: &impl AsRawFd) {
    let raw_fd = fd.as_raw_fd();
    // We need a BorrowedFd to construct the response. The fd from the
    // event is already borrowed, so we can use it directly.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw_fd) };
    let response = FanotifyResponse::new(borrowed, Response::FAN_ALLOW);
    if let Err(e) = fan.write_response(response) {
        tracing::error!(
            raw_fd,
            error = %e,
            "failed to write auto-allow fanotify response"
        );
    }
}
