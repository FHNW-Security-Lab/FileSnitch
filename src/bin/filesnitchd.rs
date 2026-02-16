use clap::Parser;
use filesnitch::daemon::{DaemonOpts, run_daemon};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "filesnitchd", version, about = "FileSnitch daemon")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "/var/lib/filesnitch/filesnitch.db")]
    db: PathBuf,
    #[arg(long, default_value = "/home")]
    home_mount: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let opts = DaemonOpts {
        config_path: args.config,
        db_path: args.db,
        home_mount_path: args.home_mount,
    };

    run_daemon(opts).await
}
