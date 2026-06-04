//! Wisp CLI — `wisp send <file>` / `wisp recv <code>`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Wisp — send anything, to anyone, instantly. Verified, end-to-end.
#[derive(Parser)]
#[command(name = "wisp", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file; prints a short code to share with the receiver.
    Send {
        /// Path to the file to send.
        file: PathBuf,
        /// Override the filename shown to the receiver.
        #[arg(long)]
        name: Option<String>,
    },
    /// Receive a file using the code shown by the sender.
    Recv {
        /// The code from the sender, e.g. `7-tiger-saturn`.
        code: String,
        /// Directory to save the received file into.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Send { file, name } => wisp_core::send_file(file, name).await,
        Command::Recv { code, dir } => wisp_core::receive_file(code, dir).await,
    }
}
