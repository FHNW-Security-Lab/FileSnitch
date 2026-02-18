use crate::config::Config;
use crate::process_info::ProcessInfo;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Built-in exclusion list that cannot be removed by users.
///
/// Uses both full-path matching and basename matching to work across
/// traditional FHS layouts and NixOS (where executables live under
/// `/nix/store/<hash>-<name>/bin/<exe>`).
pub struct ExclusionList {
    builtin_executables: HashSet<PathBuf>,
    builtin_basenames: HashSet<String>,
    builtin_prefixes: Vec<PathBuf>,
    user_executables: HashSet<PathBuf>,
    daemon_executable: Option<PathBuf>,
    min_uid: u32,
}

impl ExclusionList {
    pub fn new(config: &Config) -> Self {
        let mut builtin = HashSet::new();
        let prefixes = vec![
            PathBuf::from("/usr/lib/systemd"),
            PathBuf::from("/run/current-system"),
        ];

        // NOTE: /nix/store is NOT a prefix exclusion — it's too broad.
        // Instead, we use basename matching for specific system executables.

        // Shells
        for bin in &[
            "/bin/bash", "/bin/zsh", "/bin/fish", "/bin/sh",
            "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/fish", "/usr/bin/sh",
        ] {
            builtin.insert(PathBuf::from(bin));
        }

        // D-Bus
        for bin in &["/usr/bin/dbus-daemon", "/usr/bin/dbus-broker", "/usr/bin/dbus-broker-launch"] {
            builtin.insert(PathBuf::from(bin));
        }

        // Display servers / desktop
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

        // Basename matching: critical system executables that must be excluded
        // regardless of installation path (essential for NixOS).
        let basenames: HashSet<String> = [
            // Shells
            "bash", "zsh", "fish", "sh", "dash",
            // D-Bus
            "dbus-daemon", "dbus-broker", "dbus-broker-launch",
            // Display / desktop
            "Xorg", "Xwayland", "sway", "mutter", "kwin_wayland",
            "gnome-shell", "plasmashell", "gnome-session-binary",
            "gsd-xsettings", "gsd-color", "gsd-power", "gsd-media-keys",
            "gnome-settings-daemon", "xdg-desktop-portal", "xdg-desktop-portal-gnome",
            "xdg-desktop-portal-gtk", "xdg-desktop-portal-kde",
            "xdg-permission-store", "xdg-document-portal",
            "gvfsd", "gvfsd-fuse", "gvfs-udisks2-volume-monitor",
            "tracker-miner-fs-3", "tracker-extract-3",
            "nautilus", "thunar", "dolphin",
            // Window managers / compositors
            "gdm", "sddm", "lightdm",
            // Auth
            "login", "su", "sudo", "polkitd", "polkit-agent-helper-1",
            "fprintd", "pam_unix_passwd",
            // Package managers
            "nix", "nix-daemon", "nix-build", "nix-env", "nix-store",
            "dpkg", "apt", "apt-get", "pacman", "rpm",
            // Agents & keyring
            "gpg-agent", "ssh-agent", "gnome-keyring-daemon", "secret-tool",
            "seahorse", "gcr-ssh-agent",
            // Audio/video
            "pipewire", "wireplumber", "pulseaudio", "pactl",
            // System services
            "systemd", "systemd-resolved", "systemd-journald", "systemd-logind",
            "systemd-oomd", "systemd-timesyncd", "systemd-udevd",
            "NetworkManager", "cron", "crond", "at-spi-bus-launcher",
            "at-spi2-registryd",
            // FileSnitch itself
            "filesnitchd", "filesnitch-ui", "filesnitch",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        // Resolve the daemon's own executable from /proc/self/exe.
        let daemon_exe = std::fs::read_link("/proc/self/exe").ok();

        let user_execs = config
            .excluded_executables
            .paths
            .iter()
            .cloned()
            .collect();

        Self {
            builtin_executables: builtin,
            builtin_basenames: basenames,
            builtin_prefixes: prefixes,
            user_executables: user_execs,
            daemon_executable: daemon_exe,
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

        // The daemon's own executable (resolved at startup).
        if let Some(ref daemon_exe) = self.daemon_executable {
            if info.executable == *daemon_exe {
                return true;
            }
        }

        // Built-in executable list (exact full path).
        if self.builtin_executables.contains(&info.executable) {
            return true;
        }

        // Basename matching (works for NixOS /nix/store paths).
        if let Some(basename) = info.executable.file_name() {
            if self.builtin_basenames.contains(basename.to_string_lossy().as_ref()) {
                return true;
            }
        }

        // Built-in prefix list (for systemd unit paths).
        for prefix in &self.builtin_prefixes {
            if info.executable.starts_with(prefix) {
                return true;
            }
        }

        // User-defined exclusions.
        if self.user_executables.contains(&info.executable) {
            return true;
        }

        false
    }

    /// Return a copy of the built-in basenames for use in the fanotify
    /// reader thread's pre-filter. This allows the reader to auto-allow
    /// known excluded processes without going through the async pipeline.
    pub fn basenames_for_prefilter(&self) -> HashSet<String> {
        self.builtin_basenames.clone()
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
        self.user_exclusions_inner()
    }

    fn user_exclusions_inner(&self) -> Vec<PathBuf> {
        self.user_executables.iter().cloned().collect()
    }
}
