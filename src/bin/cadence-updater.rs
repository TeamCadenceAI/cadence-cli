use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cadence-updater", about = "Internal Cadence updater helper")]
struct Cli {
    #[arg(long)]
    manifest: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();

    if let Err(err) =
        cadence_cli::update::run_updater_helper_from_manifest_path(&cli.manifest).await
    {
        eprintln!("cadence-updater failed: {err:#}");
        std::process::exit(1);
    }
}
