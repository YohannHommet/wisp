//! Wisp CLI — `wisp send <file>` / `wisp recv <code>`.

use std::path::PathBuf;
use std::error::Error;

use clap::{Parser, Subcommand};

/// Wisp — send anything, to anyone, instantly. Verified, end-to-end.
#[derive(Parser)]
#[command(name = "wisp", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Enable verbose logging (debug level).
    #[arg(long, short, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file; prints a short code to share with the receiver.
    Send {
        /// Path to the file to send.
        file: PathBuf,
        /// Override the filename shown to the receiver.
        #[arg(long, short)]
        name: Option<String>,
        /// WAN relay URL, e.g. `http://relay.example.com:7777`.
        /// Omit for LAN-only (mDNS discovery).
        #[arg(long, short)]
        relay: Option<String>,
    },
    /// Receive a file using the code shown by the sender.
    Recv {
        /// The code from the sender, e.g. `7-tiger-saturn`.
        code: String,
        /// Directory to save the received file into.
        #[arg(long, short)]
        dir: Option<PathBuf>,
        /// WAN relay URL (must match the one used by the sender).
        #[arg(long, short)]
        relay: Option<String>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    let log_level = if cli.verbose {
        "debug,mdns_sd=warn"
    } else {
        "warn,mdns_sd=off"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // mdns-sd logs benign channel-closed errors on shutdown; silence them.
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = wisp_core::config::Config::load().unwrap_or_default();

    let result = tokio::select! {
        res = async {
            match cli.command {
                Command::Send { file, name, relay } => {
                    let env_relay = std::env::var("WISP_RELAY").ok();
                    let final_relay = config.resolve_relay(relay.as_deref(), env_relay.as_deref());
                    wisp_core::send_file(file, name, final_relay).await
                }
                Command::Recv { code, dir, relay } => {
                    let env_relay = std::env::var("WISP_RELAY").ok();
                    let final_relay = config.resolve_relay(relay.as_deref(), env_relay.as_deref());
                    let final_dir = config.resolve_download_dir(dir);
                    wisp_core::receive_file(code, final_dir, final_relay).await
                }
            }
        } => res,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\nError: Operation interrupted by user (SIGINT).");
            std::process::exit(130);
        }
    };

    if let Err(err) = result {
        eprintln!("Error: {err}");
        let mut cause = err.source();
        while let Some(c) = cause {
            eprintln!("  Caused by: {c}");
            cause = c.source();
        }
        std::process::exit(1);
    }
}
