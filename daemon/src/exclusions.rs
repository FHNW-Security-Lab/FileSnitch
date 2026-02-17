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
