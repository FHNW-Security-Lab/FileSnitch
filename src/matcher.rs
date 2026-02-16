use crate::models::{DaemonConfig, PermissionKind, ProtectionMode, Rule, RuleLayer, RuleScope, RuleStatus};
use globset::Glob;
use std::path::{Path, PathBuf};

pub fn select_protection_layer(config: &DaemonConfig, target_path: &str, home_dir: &Path) -> Option<RuleLayer> {
    if is_critical_path(config, target_path, home_dir) {
        return Some(RuleLayer::Critical);
    }
    match config.protection_mode {
        ProtectionMode::ProtectEverything => {
            let target = Path::new(target_path);
            if target.starts_with(home_dir) {
                Some(RuleLayer::Home)
            } else {
                None
            }
        }
        ProtectionMode::ProtectCriticalOnly => None,
    }
}

pub fn is_critical_path(config: &DaemonConfig, target_path: &str, home_dir: &Path) -> bool {
    let target = PathBuf::from(target_path);
    let expanded = config
        .critical_paths
        .iter()
        .map(|p| expand_home_pattern(p, home_dir))
        .collect::<Vec<_>>();
    expanded.iter().any(|pattern| glob_match(pattern, &target))
}

pub fn find_matching_rule(
    rules: &[Rule],
    executable: &str,
    target_path: &str,
    permission: PermissionKind,
    layer: RuleLayer,
    home_dir: &Path,
) -> Option<Rule> {
    rules
        .iter()
        .filter(|r| r.layer == layer && r.status() == RuleStatus::Active)
        .filter(|r| r.executable == "*" || r.executable == executable)
        .filter(|r| r.permission.allows(permission))
        .filter(|r| rule_path_matches(r, target_path, home_dir))
        .max_by_key(|r| match r.scope {
            RuleScope::ExactFile => 100,
            RuleScope::Folder => 80,
            RuleScope::FolderRecursive => 60,
            RuleScope::Custom => 40,
            RuleScope::Home => 20,
        })
        .cloned()
}

fn rule_path_matches(rule: &Rule, target_path: &str, home_dir: &Path) -> bool {
    let target = Path::new(target_path);
    match rule.scope {
        RuleScope::ExactFile => target == Path::new(&rule.path),
        RuleScope::Folder => target.parent() == Some(Path::new(&rule.path)),
        RuleScope::FolderRecursive => target.starts_with(Path::new(&rule.path)),
        RuleScope::Home => target.starts_with(home_dir),
        RuleScope::Custom => glob_match(&expand_home_pattern(&rule.path, home_dir), target),
    }
}

fn glob_match(pattern: &str, target: &Path) -> bool {
    if let Ok(glob) = Glob::new(pattern) {
        return glob.compile_matcher().is_match(target);
    }
    false
}

fn expand_home_pattern(pattern: &str, home_dir: &Path) -> String {
    if pattern == "~" || pattern.starts_with("~/") {
        return pattern.replacen('~', &home_dir.to_string_lossy(), 1);
    }
    pattern.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Action;

    #[test]
    fn critical_paths_take_priority() {
        let cfg = DaemonConfig {
            protection_mode: ProtectionMode::ProtectEverything,
            critical_paths: vec!["~/.ssh/**".to_string()],
            ..DaemonConfig::default()
        };
        let home = Path::new("/home/alice");

        let layer = select_protection_layer(&cfg, "/home/alice/.ssh/id_rsa", home);
        assert_eq!(layer, Some(RuleLayer::Critical));
    }

    #[test]
    fn exact_file_rule_matches() {
        let home = Path::new("/home/alice");
        let rule = Rule {
            id: 1,
            executable: "/usr/bin/vim".to_string(),
            path: "/home/alice/notes/todo.txt".to_string(),
            scope: RuleScope::ExactFile,
            permission: PermissionKind::ReadWrite,
            action: Action::Allow,
            layer: RuleLayer::Home,
            expires_at: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
        };
        let matched = find_matching_rule(
            &[rule.clone()],
            "/usr/bin/vim",
            "/home/alice/notes/todo.txt",
            PermissionKind::Read,
            RuleLayer::Home,
            home,
        );
        assert_eq!(matched.map(|r| r.id), Some(rule.id));
    }
}
