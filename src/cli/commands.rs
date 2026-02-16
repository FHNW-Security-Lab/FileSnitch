use crate::dbus::FileSnitchProxy;
use crate::models::{
    Action, DaemonConfig, DecisionInput, NewRule, PermissionKind, ProtectionMode, Rule, RuleLayer,
    RuleScope,
};
use anyhow::{Context, anyhow};
use clap::{Args, Parser, Subcommand};
use futures_util::StreamExt;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "filesnitch", version, about = "FileSnitch CLI")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Watch,
    Status,
    Log {
        #[arg(short, long, default_value_t = 100)]
        limit: u32,
    },
    Rules {
        #[command(subcommand)]
        command: RuleCommands,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
}

#[derive(Debug, Subcommand)]
enum RuleCommands {
    List,
    Add(RuleAddArgs),
    Remove { id: i64 },
    Edit(RuleEditArgs),
    Export { path: PathBuf },
    Import { path: PathBuf },
}

#[derive(Debug, Args)]
struct RuleAddArgs {
    #[arg(long)]
    executable: String,
    #[arg(long)]
    path: String,
    #[arg(long, default_value = "custom")]
    scope: String,
    #[arg(long, default_value = "read_write")]
    permission: String,
    #[arg(long, default_value = "allow")]
    action: String,
    #[arg(long, default_value = "home")]
    layer: String,
    #[arg(long)]
    expires_in_seconds: Option<i64>,
    #[arg(long, default_value_t = true)]
    enabled: bool,
}

#[derive(Debug, Args)]
struct RuleEditArgs {
    id: i64,
    #[arg(long)]
    executable: Option<String>,
    #[arg(long)]
    path: Option<String>,
    #[arg(long)]
    scope: Option<String>,
    #[arg(long)]
    permission: Option<String>,
    #[arg(long)]
    action: Option<String>,
    #[arg(long)]
    layer: Option<String>,
    #[arg(long)]
    expires_in_seconds: Option<i64>,
    #[arg(long)]
    enabled: Option<bool>,
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    Get,
    Set { key: String, value: String },
}

pub async fn run_cli() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let connection = zbus::Connection::system()
        .await
        .context("failed to connect to system D-Bus")?;
    let proxy = FileSnitchProxy::new(&connection)
        .await
        .context("failed to connect to filesnitchd over D-Bus")?;

    match cli.command {
        Commands::Watch => run_watch(proxy).await,
        Commands::Status => {
            let status = proxy.status().await?;
            println!("running: {}", status.running);
            println!("protection_mode: {:?}", status.protection_mode);
            println!("active_rules: {}", status.active_rule_count);
            println!("pending_requests: {}", status.pending_requests);
            Ok(())
        }
        Commands::Log { limit } => {
            let events = proxy.list_events(limit).await?;
            for event in events {
                println!(
                    "{} pid={} {} {} {:?} {:?} reason={}",
                    event.timestamp,
                    event.pid,
                    event.executable,
                    event.target_path,
                    event.permission,
                    event.action,
                    event.reason
                );
            }
            Ok(())
        }
        Commands::Rules { command } => run_rules(proxy, command).await,
        Commands::Config { command } => run_config(proxy, command).await,
    }
}

async fn run_watch(proxy: FileSnitchProxy<'_>) -> anyhow::Result<()> {
    println!("watching permission requests. press Ctrl+C to exit.");
    let mut stream = proxy.receive_permission_request().await?;

    while let Some(signal) = stream.next().await {
        let request = signal.args()?.request;
        println!();
        println!("request_id: {}", request.request_id);
        println!("app: {} ({}) pid={}", request.app_name, request.executable, request.pid);
        println!("target: {}", request.target_path);
        println!("permission: {:?}", request.permission);
        println!("layer: {:?}", request.layer);

        let action = prompt_action()?;
        let duration = prompt_duration()?;
        let scope = prompt_scope()?;
        let permission = prompt_permission()?;
        let custom_path = if scope == RuleScope::Custom {
            Some(prompt_text("custom path")?)
        } else {
            None
        };

        let submitted = proxy
            .submit_decision(DecisionInput {
                request_id: request.request_id,
                action,
                duration_seconds: duration,
                scope,
                permission,
                custom_path,
            })
            .await?;

        println!("decision submitted: {submitted}");
    }

    Ok(())
}

async fn run_rules(proxy: FileSnitchProxy<'_>, command: RuleCommands) -> anyhow::Result<()> {
    match command {
        RuleCommands::List => {
            let rules = proxy.list_rules().await?;
            for r in rules {
                println!(
                    "id={} exe={} path={} scope={:?} perm={:?} action={:?} layer={:?} enabled={} expires_at={:?}",
                    r.id,
                    r.executable,
                    r.path,
                    r.scope,
                    r.permission,
                    r.action,
                    r.layer,
                    r.enabled,
                    r.expires_at
                );
            }
        }
        RuleCommands::Add(args) => {
            let rule = NewRule {
                executable: args.executable,
                path: args.path,
                scope: parse_scope(&args.scope)?,
                permission: parse_permission(&args.permission)?,
                action: parse_action(&args.action)?,
                layer: parse_layer(&args.layer)?,
                expires_at: args.expires_in_seconds.map(|s| crate::models::now_ts() + s),
                enabled: args.enabled,
            };
            let created = proxy.add_rule(rule).await?;
            println!("created rule {}", created.id);
        }
        RuleCommands::Remove { id } => {
            proxy.delete_rule(id).await?;
            println!("removed rule {id}");
        }
        RuleCommands::Edit(args) => {
            let mut rules = proxy.list_rules().await?;
            let idx = rules.iter().position(|r| r.id == args.id).ok_or_else(|| anyhow!("rule {} not found", args.id))?;
            let mut rule: Rule = rules.swap_remove(idx);
            if let Some(v) = args.executable { rule.executable = v; }
            if let Some(v) = args.path { rule.path = v; }
            if let Some(v) = args.scope { rule.scope = parse_scope(&v)?; }
            if let Some(v) = args.permission { rule.permission = parse_permission(&v)?; }
            if let Some(v) = args.action { rule.action = parse_action(&v)?; }
            if let Some(v) = args.layer { rule.layer = parse_layer(&v)?; }
            if let Some(v) = args.expires_in_seconds { rule.expires_at = Some(crate::models::now_ts() + v); }
            if let Some(v) = args.enabled { rule.enabled = v; }
            proxy.update_rule(rule).await?;
            println!("updated rule {}", args.id);
        }
        RuleCommands::Export { path } => {
            let content = proxy.export_rules().await?;
            fs::write(&path, content)?;
            println!("exported rules to {}", path.display());
        }
        RuleCommands::Import { path } => {
            let content = fs::read_to_string(&path)?;
            let count = proxy.import_rules(content).await?;
            println!("imported {} rules", count);
        }
    }
    Ok(())
}

async fn run_config(proxy: FileSnitchProxy<'_>, command: ConfigCommands) -> anyhow::Result<()> {
    match command {
        ConfigCommands::Get => {
            let config = proxy.get_config().await?;
            println!("{}", toml::to_string_pretty(&config)?);
        }
        ConfigCommands::Set { key, value } => {
            let mut config: DaemonConfig = proxy.get_config().await?;
            match key.as_str() {
                "protection_mode" => {
                    config.protection_mode = match value.as_str() {
                        "protect_everything" => ProtectionMode::ProtectEverything,
                        "protect_critical_only" => ProtectionMode::ProtectCriticalOnly,
                        _ => return Err(anyhow!("invalid protection mode")),
                    };
                }
                "default_action_on_timeout" => config.default_action_on_timeout = parse_action(&value)?,
                "prompt_timeout_seconds" => {
                    config.prompt_timeout_seconds = value.parse().context("invalid timeout value")?;
                }
                "log_verbosity" => {
                    config.log_verbosity = value;
                }
                "excluded_executables" => {
                    config.excluded_executables = value
                        .split(',')
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                }
                "critical_paths" => {
                    config.critical_paths = value
                        .split(',')
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                }
                _ => return Err(anyhow!("unknown config key")),
            }
            proxy.set_config(config).await?;
            println!("updated config {key}");
        }
    }
    Ok(())
}

fn parse_action(v: &str) -> anyhow::Result<Action> {
    match v {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        _ => Err(anyhow!("action must be allow or deny")),
    }
}

fn parse_permission(v: &str) -> anyhow::Result<PermissionKind> {
    match v {
        "read" => Ok(PermissionKind::Read),
        "write" => Ok(PermissionKind::Write),
        "read_write" | "both" => Ok(PermissionKind::ReadWrite),
        _ => Err(anyhow!("permission must be read, write, or read_write")),
    }
}

fn parse_scope(v: &str) -> anyhow::Result<RuleScope> {
    match v {
        "exact_file" => Ok(RuleScope::ExactFile),
        "folder" => Ok(RuleScope::Folder),
        "folder_recursive" => Ok(RuleScope::FolderRecursive),
        "home" => Ok(RuleScope::Home),
        "custom" => Ok(RuleScope::Custom),
        _ => Err(anyhow!("scope must be exact_file|folder|folder_recursive|home|custom")),
    }
}

fn parse_layer(v: &str) -> anyhow::Result<RuleLayer> {
    match v {
        "home" => Ok(RuleLayer::Home),
        "critical" => Ok(RuleLayer::Critical),
        _ => Err(anyhow!("layer must be home or critical")),
    }
}

fn prompt_text(label: &str) -> anyhow::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn prompt_action() -> anyhow::Result<Action> {
    loop {
        let s = prompt_text("allow or deny [allow/deny]")?;
        if let Ok(v) = parse_action(&s) {
            return Ok(v);
        }
        println!("invalid action");
    }
}

fn prompt_duration() -> anyhow::Result<i64> {
    println!("duration:");
    println!(" 0) this time only");
    println!(" 1) 1 minute");
    println!(" 2) 10 minutes");
    println!(" 3) 60 minutes");
    println!(" 4) 12 hours");
    println!(" 5) forever");
    loop {
        let s = prompt_text("choose [0-5]")?;
        let duration = match s.as_str() {
            "0" => Some(0),
            "1" => Some(60),
            "2" => Some(600),
            "3" => Some(3600),
            "4" => Some(43200),
            "5" => Some(-1),
            _ => None,
        };
        if let Some(v) = duration {
            return Ok(v);
        }
        println!("invalid choice");
    }
}

fn prompt_scope() -> anyhow::Result<RuleScope> {
    println!("scope:");
    println!(" 0) exact file only");
    println!(" 1) folder only");
    println!(" 2) folder recursive");
    println!(" 3) entire home");
    println!(" 4) custom path");
    loop {
        let s = prompt_text("choose [0-4]")?;
        let scope = match s.as_str() {
            "0" => Some(RuleScope::ExactFile),
            "1" => Some(RuleScope::Folder),
            "2" => Some(RuleScope::FolderRecursive),
            "3" => Some(RuleScope::Home),
            "4" => Some(RuleScope::Custom),
            _ => None,
        };
        if let Some(v) = scope {
            return Ok(v);
        }
        println!("invalid choice");
    }
}

fn prompt_permission() -> anyhow::Result<PermissionKind> {
    println!("permission:");
    println!(" 0) read only");
    println!(" 1) write only");
    println!(" 2) read and write");
    loop {
        let s = prompt_text("choose [0-2]")?;
        let perm = match s.as_str() {
            "0" => Some(PermissionKind::Read),
            "1" => Some(PermissionKind::Write),
            "2" => Some(PermissionKind::ReadWrite),
            _ => None,
        };
        if let Some(v) = perm {
            return Ok(v);
        }
        println!("invalid choice");
    }
}
