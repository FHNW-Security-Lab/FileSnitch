#[tokio::main]
async fn main() -> anyhow::Result<()> {
    filesnitch::cli::commands::run_cli().await
}
