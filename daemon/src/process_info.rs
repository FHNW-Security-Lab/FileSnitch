use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};

/// Information about a process, resolved from /proc.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub executable: PathBuf,
    pub cmdline: String,
    pub uid: u32,
    pub comm: String,
}

impl ProcessInfo {
    /// Resolve process information from /proc/<pid>.
    ///
    /// Reads the executable path, command line, UID, and comm name
    /// for the given PID. Returns an error if the process does not
    /// exist or critical fields cannot be read.
    pub fn from_pid(pid: i32) -> Result<Self> {
        let proc_dir = format!("/proc/{pid}");

        // Read executable path via readlink on /proc/<pid>/exe.
        // Falls back to "<unknown>" if the symlink cannot be read
        // (e.g., the process exited or permissions are insufficient).
        let executable = fs::read_link(format!("{proc_dir}/exe"))
            .unwrap_or_else(|_| PathBuf::from("<unknown>"));

        // Read /proc/<pid>/cmdline and replace null byte separators with spaces.
        let cmdline = fs::read(format!("{proc_dir}/cmdline"))
            .map(|bytes| {
                let mut s = String::from_utf8_lossy(&bytes).into_owned();
                // The kernel separates arguments with null bytes; replace them
                // with spaces for human-readable display.
                s = s.replace('\0', " ");
                s.trim_end().to_owned()
            })
            .unwrap_or_default();

        // Read /proc/<pid>/status and extract the Uid line.
        // The Uid line has the format:
        //   Uid:    <real>  <effective>  <saved>  <filesystem>
        // We take the real UID (first field after the label).
        let status = fs::read_to_string(format!("{proc_dir}/status"))
            .with_context(|| format!("failed to read /proc/{pid}/status"))?;

        let uid = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .and_then(|line| {
                line.split_whitespace()
                    .nth(1) // real UID
                    .and_then(|val| val.parse::<u32>().ok())
            })
            .unwrap_or(0);

        // Read /proc/<pid>/comm (the kernel-level process name, max 16 chars).
        let comm = fs::read_to_string(format!("{proc_dir}/comm"))
            .map(|s| s.trim_end().to_owned())
            .unwrap_or_default();

        Ok(Self {
            pid,
            executable,
            cmdline,
            uid,
            comm,
        })
    }

    /// Check whether this process belongs to a systemd system service.
    ///
    /// Reads `/proc/<pid>/cgroup` and looks for "system.slice" in
    /// the cgroup hierarchy, which indicates the process is managed
    /// by systemd as a system-level service.
    pub fn is_system_service(&self) -> bool {
        let path = format!("/proc/{}/cgroup", self.pid);
        fs::read_to_string(path)
            .map(|content| content.contains("system.slice"))
            .unwrap_or(false)
    }
}

/// A cache of `ProcessInfo` keyed by PID.
///
/// Wraps a `Mutex<HashMap<i32, ProcessInfo>>` so it can be shared
/// across threads. Avoids repeated /proc lookups for the same PID
/// during bursts of fanotify events from the same process.
pub struct ProcessInfoCache {
    cache: Mutex<HashMap<i32, ProcessInfo>>,
}

impl ProcessInfoCache {
    /// Create a new, empty cache.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Look up cached process info for the given PID.
    ///
    /// Returns `None` if the PID is not in the cache. Does not
    /// attempt to resolve from /proc.
    pub fn get(&self, pid: i32) -> Option<ProcessInfo> {
        let cache = self.cache.lock().expect("process info cache lock poisoned");
        cache.get(&pid).cloned()
    }

    /// Resolve process info for the given PID.
    ///
    /// Returns the cached entry if available; otherwise reads from
    /// /proc, inserts into the cache, and returns the result.
    pub fn resolve(&self, pid: i32) -> Result<ProcessInfo> {
        // Fast path: return from cache without /proc I/O.
        {
            let cache = self.cache.lock().expect("process info cache lock poisoned");
            if let Some(info) = cache.get(&pid) {
                return Ok(info.clone());
            }
        }

        // Slow path: resolve from /proc and insert into cache.
        let info = ProcessInfo::from_pid(pid)?;
        {
            let mut cache = self.cache.lock().expect("process info cache lock poisoned");
            cache.insert(pid, info.clone());
        }
        Ok(info)
    }

    /// Remove cache entries for PIDs that no longer exist.
    ///
    /// Checks whether `/proc/<pid>` still exists for each cached
    /// entry and removes those that have exited. Should be called
    /// periodically to prevent unbounded cache growth.
    pub fn cleanup(&self) {
        let mut cache = self.cache.lock().expect("process info cache lock poisoned");
        cache.retain(|pid, _| {
            let proc_dir = format!("/proc/{pid}");
            PathBuf::from(&proc_dir).exists()
        });
    }
}

/// Resolve the filesystem path that a file descriptor points to.
///
/// Reads the `/proc/self/fd/<fd>` symlink to determine the actual
/// path of the open file descriptor. Used to map fanotify event
/// file descriptors back to real file paths.
pub fn resolve_fd_path(fd: i32) -> Result<PathBuf> {
    let link = format!("/proc/self/fd/{fd}");
    fs::read_link(&link).with_context(|| format!("failed to readlink {link}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_current_process() {
        let pid = std::process::id() as i32;
        let info = ProcessInfo::from_pid(pid).expect("should resolve own process");
        assert_eq!(info.pid, pid);
        assert!(!info.executable.as_os_str().is_empty());
        assert!(!info.comm.is_empty());
    }

    #[test]
    fn cache_returns_same_info() {
        let cache = ProcessInfoCache::new();
        let pid = std::process::id() as i32;
        let first = cache.resolve(pid).expect("first resolve");
        let second = cache.get(pid).expect("should be cached");
        assert_eq!(first.pid, second.pid);
        assert_eq!(first.executable, second.executable);
    }

    #[test]
    fn cleanup_removes_dead_pids() {
        let cache = ProcessInfoCache::new();
        // Insert a fake entry for a PID that certainly does not exist.
        {
            let mut inner = cache.cache.lock().unwrap();
            inner.insert(
                i32::MAX,
                ProcessInfo {
                    pid: i32::MAX,
                    executable: PathBuf::from("<gone>"),
                    cmdline: String::new(),
                    uid: 0,
                    comm: String::from("fake"),
                },
            );
        }
        cache.cleanup();
        assert!(cache.get(i32::MAX).is_none(), "dead PID should be removed");
    }

    #[test]
    fn resolve_fd_path_stdin() {
        // fd 0 (stdin) should resolve to something.
        let result = resolve_fd_path(0);
        // In a test environment stdin may or may not be a regular file,
        // but readlink should still succeed.
        assert!(result.is_ok());
    }
}
