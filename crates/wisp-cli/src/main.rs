//! Terminal adapter. Session state, authentication and file handling live in wisp-core.
#![forbid(unsafe_code)]
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::{
    io::{IsTerminal, Write},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, Mutex},
};
use wisp_core::{
    config::Config, Event, EventHandler, PairingCode, ReceiveOptions, SendOptions, TransferReceipt,
};

/// Send a file between computers on the same local network. No account or server.
#[derive(Parser)]
#[command(name = "wisp", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Emit newline-delimited JSON events, including the code and final receipt.
    #[arg(long, global = true, conflicts_with = "quiet")]
    json: bool,
    /// Hide progress and status messages (keep the code, result and errors).
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Read this TOML configuration file instead of the platform default.
    #[arg(long, global = true, conflicts_with = "no_config")]
    config: Option<PathBuf>,
    /// Ignore the user configuration file.
    #[arg(long, global = true)]
    no_config: bool,
    /// Network-operation timeout in seconds (1–3600); does not change code expiry.
    #[arg(long, global = true, value_parser = clap::value_parser!(u64).range(1..=3600))]
    timeout: Option<u64>,
    /// Enable diagnostic logs on stderr (pairing passwords are never logged).
    #[arg(short, long, global = true)]
    verbose: bool,
}
#[derive(Subcommand)]
enum Command {
    /// Send one file and print a single-use code for the receiver.
    Send {
        file: PathBuf,
        /// Filename to save on the receiver.
        #[arg(short, long)]
        name: Option<String>,
        /// Local IPv4 interface to use (useful with a VPN or multiple networks).
        #[arg(long)]
        bind: Option<Ipv4Addr>,
        /// UDP port to listen on; 0 chooses a free port.
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Skip mDNS; the receiver must also supply --address.
        #[arg(long)]
        no_discovery: bool,
        /// Expire the code after this many seconds (1–3600; default 300).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
        wait: Option<u64>,
    },
    /// Receive using the complete code printed by the sender.
    #[command(alias = "receive")]
    Recv {
        code: PairingCode,
        /// Destination directory; defaults to configuration or the current directory.
        #[arg(short, long)]
        dir: Option<PathBuf>,
        /// Sender IPv4:port; bypasses mDNS, with the same code authentication.
        #[arg(long)]
        address: Option<SocketAddr>,
        /// Maximum accepted bytes (also accepts KiB, MiB, GiB, TiB); default 1 TiB.
        #[arg(long, default_value = "1TiB", value_parser = parse_size)]
        max_size: u64,
    },
}

fn parse_size(value: &str) -> std::result::Result<u64, String> {
    let value = value.trim();
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let n: u64 = value[..split]
        .parse()
        .map_err(|_| "size must start with a nonnegative integer".to_owned())?;
    let multiplier = match value[split..].to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kib" => 1 << 10,
        "mib" => 1 << 20,
        "gib" => 1 << 30,
        "tib" => 1 << 40,
        _ => return Err("use bytes or a KiB, MiB, GiB, TiB suffix".into()),
    };
    n.checked_mul(multiplier)
        .filter(|size| *size <= wisp_core::transfer::MAX_FILE_SIZE)
        .ok_or_else(|| "size cannot exceed 1 TiB".into())
}

fn terminal_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control()
            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

struct Output {
    json: bool,
    quiet: bool,
    progress: ProgressBar,
    write_error: Mutex<Option<String>>,
    failed: tokio::sync::Notify,
}
impl Output {
    fn new(cli: &Cli) -> Self {
        let progress = if cli.json || cli.quiet || !std::io::stderr().is_terminal() {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(0)
        };
        progress.set_style(
            ProgressStyle::with_template(
                "{bar:24} {bytes}/{total_bytes}  {bytes_per_sec}  ETA {eta}",
            )
            .expect("valid progress style"),
        );
        Self {
            json: cli.json,
            quiet: cli.quiet,
            progress,
            write_error: Mutex::new(None),
            failed: tokio::sync::Notify::new(),
        }
    }
    fn output_error(&self) -> Option<String> {
        self.write_error.lock().expect("output error lock").clone()
    }
    fn record_error(&self, stream: &str, error: std::io::Error) {
        let mut failure = self.write_error.lock().expect("output error lock");
        if failure.is_none() {
            *failure = Some(format!(
                "could not write to {stream}: {error}; transfer stopped"
            ));
        }
        self.failed.notify_one();
    }
    fn stdout(&self, write: impl FnOnce(&mut std::io::StdoutLock<'_>) -> std::io::Result<()>) {
        let mut out = std::io::stdout().lock();
        if let Err(error) = write(&mut out).and_then(|_| out.flush()) {
            self.record_error("stdout", error);
        }
    }
    fn status(&self, message: &str) {
        let message = terminal_text(message);
        let result = self
            .progress
            .suspend(|| writeln!(std::io::stderr().lock(), "{message}"));
        if let Err(error) = result {
            self.record_error("stderr", error);
        }
    }
    fn line(&self, value: serde_json::Value) {
        self.stdout(|out| {
            serde_json::to_writer(&mut *out, &value).map_err(std::io::Error::other)?;
            writeln!(out)
        });
    }
    fn event(&self, event: Event) {
        if self.json {
            self.line(serde_json::to_value(event).expect("event serialization"));
            return;
        }
        match event {
            Event::Ready {
                code,
                address,
                discovery,
                expires_in,
                size,
            } => {
                self.stdout(|out| {
                    writeln!(
                        out,
                        "\nReady to send {size} bytes. Code expires in {expires_in}s.\n"
                    )?;
                    if discovery {
                        writeln!(out, "  wisp recv {code}")?;
                    } else {
                        writeln!(out, "  wisp recv {code} --address {address}")?;
                    }
                    writeln!(
                        out,
                        "\nSender address: {address}\nKeep this command running. Ctrl+C cancels.\n"
                    )
                });
            }
            Event::Progress { transferred, total } => {
                self.progress.set_length(total);
                self.progress.set_position(transferred);
            }
            Event::Warning { message } => {
                self.status(&format!("Warning: {message}"));
            }
            event if !self.quiet => {
                let message = match event {
                    Event::Preparing { name } => format!("Preparing {name}…"),
                    Event::Discovering => "Looking for the sender on this network…".into(),
                    Event::Connecting { address } => format!("Connecting to {address}…"),
                    Event::Authenticating => "Checking the pairing code…".into(),
                    Event::Verifying => "Verifying and saving…".into(),
                    Event::AwaitingReceipt => "Waiting for the receiver to verify and save…".into(),
                    _ => return,
                };
                self.status(&message);
            }
            _ => {}
        }
    }
    fn complete(&self, receipt: TransferReceipt) {
        self.progress.finish_and_clear();
        if self.json {
            self.line(serde_json::json!({"event":"completed", "receipt":receipt}));
        } else {
            self.stdout(|out| {
                if let Some(path) = receipt.saved_to {
                    writeln!(
                        out,
                        "Saved and verified: {} ({} bytes)",
                        path.display(),
                        receipt.size
                    )
                } else {
                    writeln!(
                        out,
                        "Delivered and verified: {} ({} bytes)",
                        receipt.name, receipt.size
                    )
                }
            });
        }
    }
    fn error(&self, message: &str, exit_code: u8) {
        self.progress.finish_and_clear();
        if self.json && self.output_error().is_none() {
            self.line(
                serde_json::json!({"event":"error", "message":message, "exit_code":exit_code}),
            );
        }
        if !self.json || self.output_error().is_some() {
            let diagnostic = self.output_error().unwrap_or_else(|| message.to_owned());
            // This is the last diagnostic channel. If it too is closed, retain
            // the failure exit code rather than panicking during error reporting.
            let _ = writeln!(
                std::io::stderr().lock(),
                "Error: {}",
                terminal_text(&diagnostic)
            );
        }
    }
}

async fn run(cli: Cli, events: EventHandler) -> Result<TransferReceipt> {
    let mut config = if cli.no_config {
        Config::default()
    } else {
        let required = cli.config.is_some();
        let path = match cli.config {
            Some(path) => path,
            None => Config::default_path()?,
        };
        Config::load(&path, required)?
    };
    if let Some(timeout) = cli.timeout {
        config.timeouts.pake = timeout;
        config.timeouts.discovery = timeout;
        config.timeouts.block_transfer = timeout;
    }
    match cli.command {
        Command::Send {
            file,
            name,
            bind,
            port,
            no_discovery,
            wait,
        } => {
            let mut options = SendOptions::new(file);
            options.display_name = name;
            options.bind = bind;
            options.port = port;
            options.discovery = !no_discovery;
            options.timeouts = config.timeouts;
            if let Some(wait) = wait {
                options.timeouts.wait = wait;
            }
            wisp_core::send_file(options, events).await
        }
        Command::Recv {
            code,
            dir,
            address,
            max_size,
        } => {
            let mut options = ReceiveOptions::new(code, config.download_dir(dir)?);
            options.address = address;
            options.max_size = max_size;
            options.timeouts = config.timeouts;
            wisp_core::receive_file(options, events).await
        }
    }
}

async fn interrupted() -> Result<u8> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate =
            signal(SignalKind::terminate()).context("installing termination handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => { result.context("installing interrupt handler")?; Ok(130) }
            _ = terminate.recv() => Ok(143),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("installing interrupt handler")?;
        Ok(130)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(if cli.verbose {
            "debug,mdns_sd=off"
        } else {
            "off"
        })
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    let output = Arc::new(Output::new(&cli));
    let events: EventHandler = {
        let output = output.clone();
        Arc::new(move |event| output.event(event))
    };
    // The losing transfer future is dropped before reporting cancellation. RAII
    // closes sockets and removes its partial file; process::exit would skip this.
    let result = tokio::select! {
        biased;
        signal = interrupted() => match signal {
            Ok(code) => Err((code, "transfer cancelled".to_owned())),
            Err(err) => Err((1, format!("{err:#}"))),
        },
        _ = output.failed.notified() => Err((1, output.output_error().expect("notified output error"))),
        result = run(cli, events) => result.map_err(|err| (1, format!("{err:#}"))),
    };
    match result {
        Ok(receipt) => {
            output.complete(receipt);
            if let Some(error) = output.output_error() {
                output.error(&error, 1);
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err((code, message)) => {
            output.error(&message, code);
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parser_contract() {
        Cli::command().debug_assert();
        assert!(
            Cli::try_parse_from(["wisp", "send", "file", "--relay", "http://example.com"]).is_err()
        );
        assert!(Cli::try_parse_from(["wisp", "send", "file", "--wait", "0"]).is_err());
        assert!(Cli::try_parse_from(["wisp", "recv", "7-tiger-saturn"]).is_err());
        assert_eq!(parse_size("2MiB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size("0").unwrap(), 0);
        assert!(parse_size("2TiB").is_err());
        assert!(parse_size("18446744073709551615TiB").is_err());
    }
    #[test]
    fn terminal_output_escapes_controls_and_bidi_overrides() {
        assert_eq!(
            terminal_text("peer\u{1b}[2J\n\u{202e}txt"),
            "peer\\u{1b}[2J\\n\\u{202e}txt"
        );
        assert_eq!(terminal_text("éclair"), "éclair");
    }
    use clap::CommandFactory;
}
