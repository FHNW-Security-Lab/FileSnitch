use crate::models::PermissionKind;
use anyhow::{Context, anyhow};
use std::ffi::CString;
use std::mem::size_of;
use std::os::fd::RawFd;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct KernelEvent {
    pub pid: u32,
    pub event_fd: RawFd,
    pub target_path: String,
    pub permission: PermissionKind,
}

pub struct FanotifyMonitor {
    fanotify_fd: RawFd,
}

impl FanotifyMonitor {
    pub fn new(home_mount_path: &Path) -> anyhow::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = home_mount_path;
            return Err(anyhow!("fanotify is only supported on Linux"));
        }

        #[cfg(target_os = "linux")]
        {
            let flags = libc::FAN_CLOEXEC | libc::FAN_CLASS_CONTENT;
            let fanotify_fd = unsafe {
                libc::fanotify_init(
                    flags as u32,
                    (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
                )
            };
            if fanotify_fd < 0 {
                return Err(anyhow!(
                    "fanotify_init failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let home_c = CString::new(home_mount_path.as_os_str().to_string_lossy().as_bytes())
                .context("home path contains interior null byte")?;
            let mask = libc::FAN_OPEN_PERM
                | libc::FAN_ACCESS_PERM
                | libc::FAN_EVENT_ON_CHILD
                | libc::FAN_OPEN_EXEC_PERM;
            let mark_ret = unsafe {
                libc::fanotify_mark(
                    fanotify_fd,
                    (libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT) as u32,
                    mask,
                    libc::AT_FDCWD,
                    home_c.as_ptr(),
                )
            };
            if mark_ret < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fanotify_fd);
                }
                return Err(anyhow!("fanotify_mark failed: {}", err));
            }

            Ok(Self { fanotify_fd })
        }
    }

    pub fn read_events(&self) -> anyhow::Result<Vec<KernelEvent>> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(anyhow!("fanotify is only supported on Linux"));
        }

        #[cfg(target_os = "linux")]
        {
            let mut buf = vec![0u8; 16 * 1024];
            let read_len = unsafe {
                libc::read(
                    self.fanotify_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };

            if read_len < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(Vec::new());
                }
                return Err(anyhow!("fanotify read failed: {}", e));
            }

            let mut events = Vec::new();
            let mut offset = 0usize;
            let read_len = read_len as usize;

            while offset + size_of::<libc::fanotify_event_metadata>() <= read_len {
                let meta_ptr = unsafe { buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata };
                let meta = unsafe { *meta_ptr };

                if meta.event_len == 0 {
                    break;
                }

                let advance = meta.event_len as usize;
                if advance == 0 || offset + advance > read_len {
                    break;
                }

                if meta.fd >= 0 {
                    let mask = meta.mask;
                    if (mask & (libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM | libc::FAN_OPEN_EXEC_PERM)) != 0 {
                        let event_fd = meta.fd;
                        let target_path = std::fs::read_link(format!("/proc/self/fd/{event_fd}"))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "<unknown>".to_string());
                        let permission = detect_permission(event_fd, mask)?;

                        events.push(KernelEvent {
                            pid: meta.pid as u32,
                            event_fd,
                            target_path,
                            permission,
                        });
                    } else {
                        unsafe {
                            libc::close(meta.fd);
                        }
                    }
                }

                offset += advance;
            }

            Ok(events)
        }
    }

    pub fn respond(&self, event_fd: RawFd, allow: bool) -> anyhow::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (event_fd, allow);
            return Err(anyhow!("fanotify is only supported on Linux"));
        }

        #[cfg(target_os = "linux")]
        {
            let response = libc::fanotify_response {
                fd: event_fd,
                response: if allow { libc::FAN_ALLOW } else { libc::FAN_DENY },
            };
            let wrote = unsafe {
                libc::write(
                    self.fanotify_fd,
                    &response as *const libc::fanotify_response as *const libc::c_void,
                    size_of::<libc::fanotify_response>(),
                )
            };
            unsafe {
                libc::close(event_fd);
            }
            if wrote < 0 {
                return Err(anyhow!(
                    "failed to write fanotify response: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        }
    }
}

impl Drop for FanotifyMonitor {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fanotify_fd);
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_permission(event_fd: RawFd, mask: u64) -> anyhow::Result<PermissionKind> {
    if mask & libc::FAN_ACCESS_PERM != 0 {
        return Ok(PermissionKind::Read);
    }

    if mask & libc::FAN_OPEN_EXEC_PERM != 0 {
        return Ok(PermissionKind::Read);
    }

    let flags = unsafe { libc::fcntl(event_fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(anyhow!("fcntl(F_GETFL) failed: {}", std::io::Error::last_os_error()));
    }

    match flags & libc::O_ACCMODE {
        libc::O_WRONLY => Ok(PermissionKind::Write),
        libc::O_RDWR => Ok(PermissionKind::ReadWrite),
        _ => Ok(PermissionKind::Read),
    }
}
