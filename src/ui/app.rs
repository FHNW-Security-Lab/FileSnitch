use crate::dbus::{FileSnitchProxy, FileSnitchProxyBlocking};
use crate::models::{
    Action, DecisionInput, PermissionKind, PermissionRequest, ProtectionMode, Rule,
    RuleScope,
};
use futures_util::StreamExt;
use gtk4::prelude::*;
use gtk4::{self as gtk, glib};
use std::cell::RefCell;
use std::rc::Rc;

pub fn run_ui() {
    let app = gtk::Application::builder()
        .application_id("org.filesnitch.UI")
        .build();

    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &gtk::Application) {
    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("FileSnitch")
        .default_width(1000)
        .default_height(680)
        .build();

    let notebook = gtk::Notebook::new();
    let rules_tab = build_rules_tab();
    let events_tab = build_events_tab();
    let settings_tab = build_settings_tab();

    notebook.append_page(&rules_tab.0, Some(&gtk::Label::new(Some("Rules"))));
    notebook.append_page(&events_tab.0, Some(&gtk::Label::new(Some("Event Log"))));
    notebook.append_page(&settings_tab.0, Some(&gtk::Label::new(Some("Settings"))));

    window.set_child(Some(&notebook));
    window.present();

    refresh_rules(&rules_tab.1, "");
    refresh_events(&events_tab.1, "");
    refresh_settings(&settings_tab);

    wire_permission_listener(window.clone());

    {
        let list = rules_tab.1.clone();
        let search = rules_tab.2.clone();
        rules_tab.3.connect_clicked(move |_| {
            refresh_rules(&list, &search.text());
        });
    }
    {
        let list = rules_tab.1.clone();
        let search = rules_tab.2.clone();
        rules_tab.2.connect_search_changed(move |_| {
            refresh_rules(&list, &search.text());
        });
    }

    {
        let list = events_tab.1.clone();
        let filter = events_tab.2.clone();
        events_tab.3.connect_clicked(move |_| {
            refresh_events(&list, &filter.text());
        });
    }
    {
        let list = events_tab.1.clone();
        let filter = events_tab.2.clone();
        events_tab.2.connect_search_changed(move |_| {
            refresh_events(&list, &filter.text());
        });
    }
    {
        let list = events_tab.1.clone();
        let filter = events_tab.2.clone();
        glib::timeout_add_local(std::time::Duration::from_secs(1), move || {
            refresh_events(&list, &filter.text());
            glib::ControlFlow::Continue
        });
    }

    {
        let tab = settings_tab.clone();
        settings_tab.6.connect_clicked(move |_| {
            save_settings(&tab);
        });
    }
}

#[derive(Clone)]
struct SettingsWidgets(
    gtk::Box,
    gtk::DropDown,
    gtk::SpinButton,
    gtk::DropDown,
    gtk::TextView,
    gtk::Entry,
    gtk::Button,
);

fn build_rules_tab() -> (gtk::Box, gtk::ListBox, gtk::SearchEntry, gtk::Button) {
    let container = gtk::Box::new(gtk::Orientation::Vertical, 8);
    container.set_margin_top(12);
    container.set_margin_bottom(12);
    container.set_margin_start(12);
    container.set_margin_end(12);

    let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let search = gtk::SearchEntry::new();
    search.set_placeholder_text(Some("Filter by executable/path"));
    let refresh = gtk::Button::with_label("Refresh");
    toolbar.append(&search);
    toolbar.append(&refresh);

    let scroller = gtk::ScrolledWindow::new();
    scroller.set_vexpand(true);
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    scroller.set_child(Some(&list));

    container.append(&toolbar);
    container.append(&scroller);
    (container, list, search, refresh)
}

fn build_events_tab() -> (gtk::Box, gtk::ListBox, gtk::SearchEntry, gtk::Button) {
    let container = gtk::Box::new(gtk::Orientation::Vertical, 8);
    container.set_margin_top(12);
    container.set_margin_bottom(12);
    container.set_margin_start(12);
    container.set_margin_end(12);

    let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let search = gtk::SearchEntry::new();
    search.set_placeholder_text(Some("Filter by executable/path/action"));
    let refresh = gtk::Button::with_label("Refresh");
    toolbar.append(&search);
    toolbar.append(&refresh);

    let scroller = gtk::ScrolledWindow::new();
    scroller.set_vexpand(true);
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    scroller.set_child(Some(&list));

    container.append(&toolbar);
    container.append(&scroller);
    (container, list, search, refresh)
}

fn build_settings_tab() -> SettingsWidgets {
    let container = gtk::Box::new(gtk::Orientation::Vertical, 10);
    container.set_margin_top(12);
    container.set_margin_bottom(12);
    container.set_margin_start(12);
    container.set_margin_end(12);

    let mode_model = gtk::StringList::new(&["Protect everything", "Protect critical files only"]);
    let mode = gtk::DropDown::new(Some(mode_model), None::<&gtk::Expression>);

    let timeout = gtk::SpinButton::with_range(1.0, 600.0, 1.0);

    let default_model = gtk::StringList::new(&["Deny", "Allow"]);
    let default_action = gtk::DropDown::new(Some(default_model), None::<&gtk::Expression>);

    let critical_paths = gtk::TextView::new();
    critical_paths.set_vexpand(true);

    let excluded = gtk::Entry::new();
    excluded.set_placeholder_text(Some("Comma separated executable paths"));

    let save_button = gtk::Button::with_label("Save Settings");

    container.append(&gtk::Label::new(Some("Protection mode")));
    container.append(&mode);
    container.append(&gtk::Label::new(Some("Prompt timeout (seconds)")));
    container.append(&timeout);
    container.append(&gtk::Label::new(Some("Default action on timeout")));
    container.append(&default_action);
    container.append(&gtk::Label::new(Some("Critical paths (one per line, glob supported)")));
    container.append(&critical_paths);
    container.append(&gtk::Label::new(Some("Excluded executables")));
    container.append(&excluded);
    container.append(&save_button);

    SettingsWidgets(
        container,
        mode,
        timeout,
        default_action,
        critical_paths,
        excluded,
        save_button,
    )
}

fn refresh_rules(list: &gtk::ListBox, filter: &str) {
    clear_listbox(list);
    let rules = match with_proxy_blocking(|p| p.list_rules()) {
        Ok(r) => r,
        Err(e) => {
            push_error_row(list, &format!("failed to load rules: {e}"));
            return;
        }
    };

    for rule in rules.into_iter().filter(|r| match_filter_rule(r, filter)) {
        list.append(&rule_row(&rule));
    }
}

fn refresh_events(list: &gtk::ListBox, filter: &str) {
    clear_listbox(list);
    let events = match with_proxy_blocking(|p| p.list_events(500)) {
        Ok(e) => e,
        Err(e) => {
            push_error_row(list, &format!("failed to load events: {e}"));
            return;
        }
    };

    let filter = filter.to_lowercase();
    for event in events {
        let row_text = format!(
            "{} | {} | {} | {:?} | {:?} | {}",
            event.timestamp,
            event.executable,
            event.target_path,
            event.permission,
            event.action,
            event.reason
        );
        if !filter.is_empty() && !row_text.to_lowercase().contains(&filter) {
            continue;
        }
        let label = gtk::Label::new(Some(&row_text));
        label.set_xalign(0.0);
        list.append(&label);
    }
}

fn refresh_settings(settings: &SettingsWidgets) {
    let cfg = match with_proxy_blocking(|p| p.get_config()) {
        Ok(c) => c,
        Err(_) => return,
    };

    match cfg.protection_mode {
        ProtectionMode::ProtectEverything => settings.1.set_selected(0),
        ProtectionMode::ProtectCriticalOnly => settings.1.set_selected(1),
    }
    settings.2.set_value(cfg.prompt_timeout_seconds as f64);
    match cfg.default_action_on_timeout {
        Action::Deny => settings.3.set_selected(0),
        Action::Allow => settings.3.set_selected(1),
    }

    let buf = settings.4.buffer();
    buf.set_text(&cfg.critical_paths.join("\n"));
    settings.5.set_text(&cfg.excluded_executables.join(","));
}

fn save_settings(settings: &SettingsWidgets) {
    let mut cfg = match with_proxy_blocking(|p| p.get_config()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config: {e}");
            return;
        }
    };

    cfg.protection_mode = if settings.1.selected() == 0 {
        ProtectionMode::ProtectEverything
    } else {
        ProtectionMode::ProtectCriticalOnly
    };
    cfg.prompt_timeout_seconds = settings.2.value() as u64;
    cfg.default_action_on_timeout = if settings.3.selected() == 0 {
        Action::Deny
    } else {
        Action::Allow
    };

    let buf = settings.4.buffer();
    let text = buf.text(&buf.start_iter(), &buf.end_iter(), true).to_string();
    cfg.critical_paths = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    cfg.excluded_executables = settings
        .5
        .text()
        .split(',')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    if let Err(e) = with_proxy_blocking(|p| p.set_config(cfg)) {
        eprintln!("failed to save config: {e}");
    }
}

fn wire_permission_listener(window: gtk::ApplicationWindow) {
    let (tx, rx) = std::sync::mpsc::channel::<PermissionRequest>();
    spawn_permission_thread(tx);

    let rx = Rc::new(RefCell::new(rx));
    glib::timeout_add_local(std::time::Duration::from_millis(200), move || {
        while let Ok(request) = rx.borrow().try_recv() {
            show_permission_dialog(&window, request);
        }
        glib::ControlFlow::Continue
    });
}

fn spawn_permission_thread(tx: std::sync::mpsc::Sender<PermissionRequest>) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("failed to create tokio runtime for UI signal thread: {e}");
                return;
            }
        };

        runtime.block_on(async move {
            let conn = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to connect system bus in UI: {e}");
                    return;
                }
            };

            let proxy = match FileSnitchProxy::new(&conn).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("failed to build proxy in UI signal thread: {e}");
                    return;
                }
            };

            let mut stream = match proxy.receive_permission_request().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("failed to subscribe permission_request signal: {e}");
                    return;
                }
            };

            while let Some(signal) = stream.next().await {
                if let Ok(args) = signal.args() {
                    let _ = tx.send(args.request.clone());
                }
            }
        });
    });
}

fn show_permission_dialog(window: &gtk::ApplicationWindow, request: PermissionRequest) {
    let dialog = gtk::Dialog::builder()
        .title("File access request")
        .modal(true)
        .transient_for(window)
        .default_width(560)
        .default_height(340)
        .build();

    dialog.add_button("Deny", gtk::ResponseType::Reject);
    dialog.add_button("Allow", gtk::ResponseType::Accept);

    let content = dialog.content_area();
    content.set_spacing(8);

    let icon = gtk::Image::from_icon_name("application-x-executable");
    icon.set_pixel_size(36);
    content.append(&icon);

    let details = gtk::Label::new(Some(&format!(
        "Application: {}\nExecutable: {}\nPID: {}\nTarget: {}\nPermission: {:?}",
        request.app_name, request.executable, request.pid, request.target_path, request.permission
    )));
    details.set_wrap(true);
    details.set_xalign(0.0);
    content.append(&details);

    let action_dd = dropdown(&["Allow", "Deny"]);
    action_dd.set_selected(0);
    let duration_dd = dropdown(&[
        "This time only",
        "1 minute",
        "10 minutes",
        "60 minutes",
        "12 hours",
        "Forever",
    ]);
    let scope_dd = dropdown(&[
        "This exact file only",
        "This folder",
        "This folder and subfolders",
        "Entire home directory",
        "Custom path",
    ]);
    let permission_dd = dropdown(&["Read only", "Write only", "Read and write"]);
    permission_dd.set_selected(2);

    let custom_path = gtk::Entry::new();
    custom_path.set_placeholder_text(Some("Custom path or glob"));
    custom_path.set_visible(false);

    {
        let custom_path = custom_path.clone();
        scope_dd.connect_selected_notify(move |dd| {
            custom_path.set_visible(dd.selected() == 4);
        });
    }

    content.append(&gtk::Label::new(Some("Action")));
    content.append(&action_dd);
    content.append(&gtk::Label::new(Some("Duration")));
    content.append(&duration_dd);
    content.append(&gtk::Label::new(Some("Rule path scope")));
    content.append(&scope_dd);
    content.append(&gtk::Label::new(Some("Permission type")));
    content.append(&permission_dd);
    content.append(&custom_path);

    let request_id = request.request_id.clone();
    dialog.connect_response(move |d, resp| {
        let action = match resp {
            gtk::ResponseType::Accept => Action::Allow,
            _ => Action::Deny,
        };

        let duration_seconds = match duration_dd.selected() {
            0 => 0,
            1 => 60,
            2 => 600,
            3 => 3600,
            4 => 43200,
            _ => -1,
        };

        let scope = match scope_dd.selected() {
            0 => RuleScope::ExactFile,
            1 => RuleScope::Folder,
            2 => RuleScope::FolderRecursive,
            3 => RuleScope::Home,
            _ => RuleScope::Custom,
        };

        let permission = match permission_dd.selected() {
            0 => PermissionKind::Read,
            1 => PermissionKind::Write,
            _ => PermissionKind::ReadWrite,
        };

        let decision = DecisionInput {
            request_id: request_id.clone(),
            action,
            duration_seconds,
            scope,
            permission,
            custom_path: if scope == RuleScope::Custom {
                let v = custom_path.text().to_string();
                if v.is_empty() {
                    None
                } else {
                    Some(v)
                }
            } else {
                None
            },
        };

        std::thread::spawn(move || {
            if let Err(e) = with_proxy_blocking(|p| p.submit_decision(decision)) {
                eprintln!("failed to submit decision: {e}");
            }
        });

        d.close();
    });

    dialog.present();
}

fn with_proxy_blocking<T>(f: impl FnOnce(FileSnitchProxyBlocking<'_>) -> zbus::Result<T>) -> anyhow::Result<T> {
    let conn = zbus::blocking::Connection::system()?;
    let proxy = FileSnitchProxyBlocking::new(&conn)?;
    Ok(f(proxy)?)
}

fn dropdown(items: &[&str]) -> gtk::DropDown {
    let model = gtk::StringList::new(items);
    gtk::DropDown::new(Some(model), None::<&gtk::Expression>)
}

fn clear_listbox(list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

fn push_error_row(list: &gtk::ListBox, msg: &str) {
    let label = gtk::Label::new(Some(msg));
    label.set_xalign(0.0);
    list.append(&label);
}

fn match_filter_rule(rule: &Rule, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let f = filter.to_lowercase();
    rule.executable.to_lowercase().contains(&f) || rule.path.to_lowercase().contains(&f)
}

fn rule_row(rule: &Rule) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_hexpand(true);
    let text = format!(
        "#{} | {} | {} | {:?} | {:?} | {:?} | enabled={} | expires_at={:?}",
        rule.id,
        rule.executable,
        rule.path,
        rule.scope,
        rule.permission,
        rule.action,
        rule.enabled,
        rule.expires_at,
    );
    let label = gtk::Label::new(Some(&text));
    label.set_xalign(0.0);
    label.set_wrap(true);
    row.append(&label);

    let rule_id = rule.id;
    let next_enabled = !rule.enabled;
    let toggle = gtk::Button::with_label(if rule.enabled { "Disable" } else { "Enable" });
    toggle.connect_clicked(move |_| {
        if let Err(e) = with_proxy_blocking(|p| p.toggle_rule(rule_id, next_enabled)) {
            eprintln!("failed to toggle rule {rule_id}: {e}");
        }
    });
    row.append(&toggle);

    let rule_id = rule.id;
    let delete = gtk::Button::with_label("Delete");
    delete.connect_clicked(move |_| {
        if let Err(e) = with_proxy_blocking(|p| p.delete_rule(rule_id)) {
            eprintln!("failed to delete rule {rule_id}: {e}");
        }
    });
    row.append(&delete);
    row
}
