//! WSP/2: channel-bound PAKE → GET → metadata + bytes + EOF → verified receipt.
//! A sender succeeds only after the receiver reports a verified, published file.
use crate::{
    config::Timeouts,
    discovery, pake,
    storage::{sanitize, sanitize_relative_path, PendingDirectory, ResumableFile},
    transport, PairingCode,
};
use anyhow::{anyhow, bail, Context, Result};
use quinn::{Endpoint, RecvStream, SendStream, TokioRuntime};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

const CHUNK: usize = 64 * 1024;
// Amortize Tokio's blocking-file handoff while keeping preparation memory bounded.
const HASH_CHUNK: usize = 256 * 1024;
const MAX_FRAME: usize = 64 * 1024;
pub const MAX_FILE_SIZE: u64 = 1 << 40;
// Minimum bytes transferred per io timeout window to mitigate Slowloris resource exhaustion.
const MIN_THROUGHPUT_PER_WINDOW: u64 = 16 * 1024;

/// Events are synchronous and ordered; handlers should return promptly.
/// Ready contains the secret code: do not send events to external telemetry.
pub type EventHandler = Arc<dyn Fn(Event) + Send + Sync>;

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Preparing {
        name: String,
    },
    Ready {
        code: String,
        address: SocketAddr,
        discovery: bool,
        expires_in: u64,
        size: u64,
        #[serde(default)]
        is_directory: bool,
    },
    Discovering,
    Connecting {
        address: SocketAddr,
    },
    Authenticating,
    Progress {
        transferred: u64,
        total: u64,
    },
    Resuming {
        offset: u64,
        total: u64,
    },
    Verifying,
    AwaitingReceipt,
    Warning {
        message: String,
    },
}

#[derive(Clone, Debug)]
pub struct SendOptions {
    pub path: PathBuf,
    pub display_name: Option<String>,
    pub bind: Option<Ipv4Addr>,
    pub port: u16,
    pub discovery: bool,
    pub timeouts: Timeouts,
}
impl SendOptions {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            display_name: None,
            bind: None,
            port: 0,
            discovery: true,
            timeouts: Timeouts::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReceiveOptions {
    pub code: PairingCode,
    pub directory: PathBuf,
    pub address: Option<SocketAddr>,
    pub max_size: u64,
    pub timeouts: Timeouts,
    pub resume: bool,
}
impl ReceiveOptions {
    pub fn new(code: PairingCode, directory: PathBuf) -> Self {
        Self {
            code,
            directory,
            address: None,
            max_size: MAX_FILE_SIZE,
            timeouts: Timeouts::default(),
            resume: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferReceipt {
    pub name: String,
    pub size: u64,
    pub hash: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_saved_path"
    )]
    pub saved_to: Option<PathBuf>,
    #[serde(default)]
    pub is_directory: bool,
}

fn serialize_saved_path<S: serde::Serializer>(
    path: &Option<PathBuf>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // JSON strings cannot represent arbitrary native filenames. The Rust API
    // retains the exact PathBuf; terminal/JSON paths use the OS display form.
    path.as_ref()
        .map(|path| path.to_string_lossy())
        .serialize(serializer)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileMeta {
    name: String,
    size: u64,
    hash: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    is_directory: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entries_count: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedReceipt {
    name: String,
    size: u64,
    hash: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    is_directory: bool,
}

pub const CHECKPOINT_INTERVAL: u64 = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum TransferRequest {
    Full,
    Resume { offset: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum TransferResponse {
    Accepted { start_offset: u64 },
    Rejected { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DirFrame {
    Dir {
        path: String,
    },
    FileHeader {
        path: String,
        size: u64,
        executable: bool,
    },
    FileEnd {
        hash: String,
    },
    EndDir {
        root_hash: String,
    },
}

struct PreparedFile {
    file: File,
    meta: FileMeta,
}
impl PreparedFile {
    async fn open(options: &SendOptions, events: &EventHandler) -> Result<Self> {
        let mut file = File::open(&options.path)
            .await
            .context("opening source file")?;
        let stat = file.metadata().await?;
        if !stat.is_file() || stat.len() > MAX_FILE_SIZE {
            bail!("source must be a regular file of at most 1 TiB");
        }
        let name = sanitize(options.display_name.as_deref().unwrap_or_else(|| {
            options
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
        }));
        events(Event::Preparing { name: name.clone() });
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0; HASH_CHUNK];
        let mut size = 0;
        loop {
            let n = file
                .read(&mut buffer)
                .await
                .context("hashing source file")?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > stat.len() {
                bail!("source file changed while preparing; stop editing it and retry");
            }
            hasher.update(&buffer[..n]);
        }
        if size != stat.len() {
            bail!("source file changed while preparing; retry");
        }
        file.rewind().await?;
        Ok(Self {
            file,
            meta: FileMeta {
                name,
                size,
                hash: hasher.finalize().to_hex().to_string(),
                is_directory: false,
                entries_count: None,
            },
        })
    }
}

enum DirScanEntry {
    Directory {
        rel_path: String,
    },
    File {
        rel_path: String,
        size: u64,
        executable: bool,
    },
}

impl DirScanEntry {
    fn wire_path(&self) -> &str {
        match self {
            Self::Directory { rel_path } => rel_path,
            Self::File { rel_path, .. } => rel_path,
        }
    }
}

struct PreparedDirectory {
    root: PathBuf,
    name: String,
    total_size: u64,
    entries: Vec<DirScanEntry>,
}

impl PreparedDirectory {
    async fn open(options: &SendOptions, events: &EventHandler) -> Result<Self> {
        let root = options
            .path
            .canonicalize()
            .with_context(|| format!("resolving directory path {}", options.path.display()))?;
        let name = sanitize(options.display_name.as_deref().unwrap_or_else(|| {
            options
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("directory")
        }));
        events(Event::Preparing { name: name.clone() });

        let root_for_scan = root.clone();
        let events_for_scan = Arc::clone(events);
        let (entries, total_size) =
            tokio::task::spawn_blocking(move || scan_directory(&root_for_scan, &events_for_scan))
                .await
                .context("directory scan panicked")??;

        Ok(Self {
            root,
            name,
            total_size,
            entries,
        })
    }
}

enum PreparedSource {
    File(PreparedFile),
    Directory(PreparedDirectory),
}

impl PreparedSource {
    async fn open(options: &SendOptions, events: &EventHandler) -> Result<Self> {
        let meta = tokio::fs::metadata(&options.path)
            .await
            .with_context(|| format!("cannot read {}", options.path.display()))?;
        if meta.is_file() {
            Ok(Self::File(PreparedFile::open(options, events).await?))
        } else if meta.is_dir() {
            Ok(Self::Directory(
                PreparedDirectory::open(options, events).await?,
            ))
        } else {
            bail!("send accepts a regular file or directory; special files are not supported");
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::File(f) => f.meta.size,
            Self::Directory(d) => d.total_size,
        }
    }

    fn is_directory(&self) -> bool {
        matches!(self, Self::Directory(_))
    }
}

fn scan_directory(root: &Path, events: &EventHandler) -> Result<(Vec<DirScanEntry>, u64)> {
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(PathBuf::new());
    let mut entries = Vec::new();
    let mut total_size: u64 = 0;

    while let Some(rel_dir) = queue.pop_front() {
        let abs_dir = root.join(&rel_dir);
        let read_dir = std::fs::read_dir(&abs_dir)
            .with_context(|| format!("reading directory {}", abs_dir.display()))?;

        for entry in read_dir {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_str().ok_or_else(|| {
                anyhow::anyhow!("non-UTF-8 filename in directory: {:?}", file_name)
            })?;
            let rel_entry = if rel_dir.as_os_str().is_empty() {
                PathBuf::from(file_name_str)
            } else {
                rel_dir.join(file_name_str)
            };

            let depth = rel_entry.components().count();
            if depth > 32 {
                bail!(
                    "directory nesting exceeds maximum depth of 32 levels at {}",
                    rel_entry.display()
                );
            }

            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                events(Event::Warning {
                    message: format!(
                        "skipping symlink '{}'; symlinks are not transferred",
                        rel_entry.display()
                    ),
                });
                continue;
            }

            let wire_path = rel_entry
                .components()
                .map(|c| {
                    c.as_os_str().to_str().ok_or_else(|| {
                        anyhow!("non-UTF-8 path component in '{}'", rel_entry.display())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");

            // Validate that the relative path complies with wire security rules
            sanitize_relative_path(&wire_path).with_context(|| {
                format!(
                    "source directory contains unportable or unsafe path '{}'",
                    wire_path
                )
            })?;

            if file_type.is_dir() {
                entries.push(DirScanEntry::Directory {
                    rel_path: wire_path,
                });
                queue.push_back(rel_entry);
            } else if file_type.is_file() {
                let metadata = entry.metadata()?;
                let size = metadata.len();
                total_size = total_size.checked_add(size).ok_or_else(|| {
                    anyhow::anyhow!("directory total size exceeds 64-bit integer")
                })?;
                if total_size > MAX_FILE_SIZE {
                    bail!("directory total size exceeds maximum limit of 1 TiB");
                }
                #[cfg(unix)]
                let executable = {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let executable = false;

                entries.push(DirScanEntry::File {
                    rel_path: wire_path,
                    size,
                    executable,
                });
            } else {
                events(Event::Warning {
                    message: format!("skipping special file '{}'", rel_entry.display()),
                });
            }

            if entries.len() > 100_000 {
                bail!("directory contains more than 100,000 entries");
            }
        }
    }

    entries.sort_by(|a, b| a.wire_path().cmp(b.wire_path()));
    Ok((entries, total_size))
}

/// Create a fresh code, bind a single LAN interface and serve one receiver.
/// Dropping this future withdraws discovery and closes its endpoint.
pub async fn send_file(options: SendOptions, events: EventHandler) -> Result<TransferReceipt> {
    options.timeouts.validate()?;
    let mut source = PreparedSource::open(&options, &events).await?;
    let ip = match options.bind {
        Some(ip) if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() => ip,
        Some(_) => bail!("--bind must be a specific local IPv4 address"),
        None => match local_ip_address::local_ip().context("no local address; use --bind with your LAN IPv4 address")? {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => bail!("automatic discovery currently requires IPv4; use --bind with your LAN IPv4 address"),
        },
    };
    let setup = transport::make_server_config()?;
    let endpoint =
        endpoint_with_socket(Some(setup.config), SocketAddr::new(ip.into(), options.port))
            .context("cannot listen on that address/port; check --bind and --port")?;
    let address = endpoint.local_addr()?;
    let code = PairingCode::generate();
    let advert = if options.discovery {
        match discovery::advertise(&code, ip, address.port(), &setup.fingerprint) {
            Ok(advert) => Some(advert),
            Err(err) => {
                events(Event::Warning { message: format!("local discovery unavailable ({err:#}); receiver must use --address {address}") });
                None
            }
        }
    } else {
        None
    };
    events(Event::Ready {
        code: code.expose().into(),
        address,
        discovery: advert.is_some(),
        expires_in: options.timeouts.wait,
        size: source.size(),
        is_directory: source.is_directory(),
    });

    const MAX_PRE_AUTH_RETRIES: usize = 3;
    let mut pre_auth_retries = 0;
    let deadline = Instant::now() + Duration::from_secs(options.timeouts.wait);

    let (conn, mut send, mut recv) = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("code expired while waiting for a receiver; run send again for a fresh code");
        }
        let incoming = match tokio::time::timeout(remaining, async {
            loop {
                let incoming = endpoint.accept().await.context("sender endpoint closed")?;
                if !incoming.remote_address_validated() {
                    incoming
                        .retry()
                        .context("validating the receiver's network address")?;
                    continue;
                }
                return Ok::<_, anyhow::Error>(incoming);
            }
        })
        .await
        {
            Ok(Ok(incoming)) => incoming,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                bail!("code expired while waiting for a receiver; run send again for a fresh code");
            }
        };

        let conn = match tokio::time::timeout(Duration::from_secs(options.timeouts.pake), incoming)
            .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) => {
                pre_auth_retries += 1;
                if pre_auth_retries >= MAX_PRE_AUTH_RETRIES {
                    bail!("connection handshake failed: {err:#}; exceeded pre-auth retry limit");
                }
                events(Event::Warning {
                    message: format!(
                        "connection handshake failed before authentication ({err:#}); waiting for receiver"
                    ),
                });
                continue;
            }
            Err(_) => {
                pre_auth_retries += 1;
                if pre_auth_retries >= MAX_PRE_AUTH_RETRIES {
                    bail!("connection handshake timed out; exceeded pre-auth retry limit");
                }
                events(Event::Warning {
                    message:
                        "connection handshake timed out before authentication; waiting for receiver"
                            .into(),
                });
                continue;
            }
        };

        match tokio::time::timeout(Duration::from_secs(options.timeouts.pake), conn.accept_bi())
            .await
        {
            Ok(Ok((send, recv))) => break (conn, send, recv),
            Ok(Err(err)) => {
                pre_auth_retries += 1;
                if pre_auth_retries >= MAX_PRE_AUTH_RETRIES {
                    bail!("receiver did not open a stream: {err:#}; exceeded pre-auth retry limit");
                }
                events(Event::Warning {
                    message: format!(
                        "receiver disconnected before opening a stream ({err:#}); waiting for receiver"
                    ),
                });
                continue;
            }
            Err(_) => {
                pre_auth_retries += 1;
                if pre_auth_retries >= MAX_PRE_AUTH_RETRIES {
                    bail!("receiver stream opening timed out; exceeded pre-auth retry limit");
                }
                events(Event::Warning {
                    message: "receiver stream opening timed out; waiting for receiver".into(),
                });
                continue;
            }
        }
    };

    // One attempt per code once authentication begins; no guess-retry oracle.
    drop(advert);
    let binding = channel_binding(&conn)?;
    let result = sender_protocol(
        &code,
        &mut source,
        &mut send,
        &mut recv,
        &binding,
        &options.timeouts,
        &events,
    )
    .await;
    if result.is_ok() {
        // Receipt is already validated. Allow its transport ACK to reach the receiver
        // before tearing down, so it can confidently finish its own command.
        let _ = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await;
    }
    conn.close(0u32.into(), b"session finished");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    result
}

/// Receive into a private temporary file, verify it and publish without overwriting.
pub async fn receive_file(
    options: ReceiveOptions,
    events: EventHandler,
) -> Result<TransferReceipt> {
    options.timeouts.validate()?;
    if options.max_size > MAX_FILE_SIZE {
        bail!("maximum receive size cannot exceed 1 TiB");
    }
    let (address, fingerprint) = match options.address {
        Some(address) => {
            if !address.is_ipv4()
                || address.port() == 0
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
            {
                bail!("--address must be the sender's IPv4 address and nonzero port");
            }
            (address, None)
        }
        None => {
            events(Event::Discovering);
            let peer = discovery::find(
                &options.code,
                Duration::from_secs(options.timeouts.discovery),
            )
            .await?;
            (peer.address, Some(peer.fingerprint))
        }
    };
    events(Event::Connecting { address });
    let mut endpoint =
        endpoint_with_socket(None, SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))?;
    endpoint.set_default_client_config(transport::make_client_config(fingerprint)?);
    let conn = tokio::time::timeout(
        Duration::from_secs(options.timeouts.pake),
        endpoint.connect(address, "wisp")?,
    )
    .await
    .context("cannot reach sender; check Wi-Fi, firewall and the sender's --bind address")?
    .context("connecting to sender; both computers need Wisp 0.2 or newer")?;
    let result = async {
        let (mut send, mut recv) =
            tokio::time::timeout(Duration::from_secs(options.timeouts.pake), conn.open_bi())
                .await
                .context("sender did not allow authentication before the timeout")??;
        let binding = channel_binding(&conn)?;
        receiver_protocol(&options, &mut send, &mut recv, &binding, &events).await
    }
    .await;
    conn.close(0u32.into(), b"session finished");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    result
}

fn endpoint_with_socket(
    server_config: Option<quinn::ServerConfig>,
    address: SocketAddr,
) -> std::io::Result<Endpoint> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    // Large UDP buffers prevent kernel drops from turning normal reordering into
    // Quinn's bounded-gap transport error on high-throughput LAN transfers.
    // Try descending sizes independently and continue with OS defaults if all fail,
    // ensuring cross-platform compatibility on macOS/BSDs where kern.ipc.maxsockbuf is lower.
    for size in [
        16 * 1024 * 1024,
        8 * 1024 * 1024,
        4 * 1024 * 1024,
        1024 * 1024,
    ] {
        if socket.set_recv_buffer_size(size).is_ok() {
            break;
        }
    }
    for size in [
        16 * 1024 * 1024,
        8 * 1024 * 1024,
        4 * 1024 * 1024,
        1024 * 1024,
    ] {
        if socket.set_send_buffer_size(size).is_ok() {
            break;
        }
    }
    socket.bind(&address.into())?;
    Endpoint::new(
        Default::default(),
        server_config,
        socket.into(),
        Arc::new(TokioRuntime),
    )
}

fn channel_binding(conn: &quinn::Connection) -> Result<[u8; 32]> {
    let mut binding = [0; 32];
    conn.export_keying_material(&mut binding, b"wisp-v2-channel-binding", &[])
        .map_err(|err| anyhow::anyhow!("TLS channel binding failed: {err:?}"))?;
    Ok(binding)
}

async fn sender_protocol(
    code: &PairingCode,
    source: &mut PreparedSource,
    send: &mut SendStream,
    recv: &mut RecvStream,
    binding: &[u8; 32],
    timeouts: &Timeouts,
    events: &EventHandler,
) -> Result<TransferReceipt> {
    events(Event::Authenticating);
    tokio::time::timeout(
        Duration::from_secs(timeouts.pake),
        pake::sender_handshake(code.expose(), send, recv, binding),
    )
    .await
    .context("authentication timed out; start a new transfer")?
    .context("authentication failed; check the code and start a new transfer")?;
    let mut ready = [0; 3];
    tokio::time::timeout(timeouts.io(), recv.read_exact(&mut ready))
        .await
        .context("receiver ready signal timed out")??;
    if &ready != b"GET" {
        bail!("invalid receiver request");
    }

    match source {
        PreparedSource::File(file) => {
            sender_file_protocol(file, send, recv, timeouts, events).await
        }
        PreparedSource::Directory(dir) => {
            sender_dir_protocol(dir, send, recv, timeouts, events).await
        }
    }
}

async fn sender_file_protocol(
    source: &mut PreparedFile,
    send: &mut SendStream,
    recv: &mut RecvStream,
    timeouts: &Timeouts,
    events: &EventHandler,
) -> Result<TransferReceipt> {
    write_frame(send, &source.meta, timeouts.io()).await?;

    let req: TransferRequest = read_frame(recv, timeouts.io()).await?;
    let start_offset = match req {
        TransferRequest::Full => {
            write_frame(
                send,
                &TransferResponse::Accepted { start_offset: 0 },
                timeouts.io(),
            )
            .await?;
            0u64
        }
        TransferRequest::Resume { offset } => {
            if offset > source.meta.size {
                let reason = format!(
                    "resume offset {offset} exceeds source size {}",
                    source.meta.size
                );
                write_frame(
                    send,
                    &TransferResponse::Rejected {
                        reason: reason.clone(),
                    },
                    timeouts.io(),
                )
                .await?;
                bail!("rejected invalid resume request: {reason}");
            }
            if offset % CHECKPOINT_INTERVAL != 0 && offset != 0 {
                let reason = format!(
                    "resume offset {offset} is not aligned to checkpoint boundary {CHECKPOINT_INTERVAL}"
                );
                write_frame(
                    send,
                    &TransferResponse::Rejected {
                        reason: reason.clone(),
                    },
                    timeouts.io(),
                )
                .await?;
                bail!("rejected misaligned resume request: {reason}");
            }
            source
                .file
                .seek(std::io::SeekFrom::Start(offset))
                .await
                .context("seeking source file for resume")?;
            write_frame(
                send,
                &TransferResponse::Accepted {
                    start_offset: offset,
                },
                timeouts.io(),
            )
            .await?;
            offset
        }
    };

    if start_offset > 0 {
        events(Event::Resuming {
            offset: start_offset,
            total: source.meta.size,
        });
    }

    let mut progress = Progress::new(start_offset, source.meta.size, events);
    let mut buf = vec![0; CHUNK];
    let mut sent = start_offset;
    progress.update(sent);
    let mut hash = blake3::Hasher::new();
    let mut window_start = Instant::now();
    let mut window_start_sent = start_offset;
    while sent < source.meta.size {
        let to_read = ((source.meta.size - sent).min(CHUNK as u64)) as usize;
        let n = source
            .file
            .read(&mut buf[..to_read])
            .await
            .context("reading source file")?;
        if n == 0 {
            break;
        }
        if sent + n as u64 > source.meta.size {
            bail!("source file grew during transfer; receiver must retry");
        }
        if start_offset == 0 {
            hash.update(&buf[..n]);
        }
        tokio::time::timeout(timeouts.io(), send.write_all(&buf[..n]))
            .await
            .context("sending stalled")??;
        sent += n as u64;
        progress.update(sent);

        let elapsed = window_start.elapsed();
        if elapsed >= timeouts.io() {
            let bytes_in_window = sent - window_start_sent;
            let remaining_expected = source.meta.size - window_start_sent;
            let min_required = MIN_THROUGHPUT_PER_WINDOW.min(remaining_expected);
            if bytes_in_window < min_required && sent < source.meta.size {
                bail!("transfer rate too slow; aborted to prevent connection starvation");
            }
            window_start = Instant::now();
            window_start_sent = sent;
        }
    }
    if sent != source.meta.size {
        bail!("source file changed during transfer; receiver must retry");
    }
    if start_offset == 0 && hash.finalize().to_hex().as_str() != source.meta.hash {
        bail!("source file changed during transfer; receiver must retry");
    }
    send.finish()?;
    events(Event::AwaitingReceipt);
    let receipt: VerifiedReceipt = read_frame(recv, timeouts.io()).await
        .context("delivery unconfirmed: receiver did not acknowledge a verified save; check the destination before retrying")?;
    expect_eof(recv, timeouts.io()).await?;
    if receipt.is_directory
        || receipt.size != source.meta.size
        || receipt.hash != source.meta.hash
        || receipt.name.is_empty()
        || receipt.name.len() > 240
        || receipt.name.contains(['/', '\\'])
        || receipt.name == "."
        || receipt.name == ".."
        || receipt.name.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '\u{200e}'
                        | '\u{200f}'
                        | '\u{061c}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
    {
        bail!("invalid delivery receipt; transfer not confirmed");
    }
    Ok(TransferReceipt {
        name: receipt.name,
        size: receipt.size,
        hash: receipt.hash,
        saved_to: None,
        is_directory: false,
    })
}

async fn sender_dir_protocol(
    dir: &mut PreparedDirectory,
    send: &mut SendStream,
    recv: &mut RecvStream,
    timeouts: &Timeouts,
    events: &EventHandler,
) -> Result<TransferReceipt> {
    let meta = FileMeta {
        name: dir.name.clone(),
        size: dir.total_size,
        hash: String::new(),
        is_directory: true,
        entries_count: Some(dir.entries.len() as u64),
    };
    write_frame(send, &meta, timeouts.io()).await?;

    let mut progress = Progress::new(0, dir.total_size, events);
    let mut buf = vec![0; CHUNK];
    let mut sent = 0u64;
    let mut tree_hasher = blake3::Hasher::new();
    tree_hasher.update(b"WISP_DIR_V1\0");
    let mut window_start = Instant::now();
    let mut window_start_sent = 0u64;

    for entry in &dir.entries {
        match entry {
            DirScanEntry::Directory { rel_path } => {
                tree_hasher.update(b"D\0");
                tree_hasher.update(&(rel_path.len() as u32).to_be_bytes());
                tree_hasher.update(rel_path.as_bytes());
                write_frame(
                    send,
                    &DirFrame::Dir {
                        path: rel_path.clone(),
                    },
                    timeouts.io(),
                )
                .await?;
            }
            DirScanEntry::File {
                rel_path,
                size,
                executable,
            } => {
                let abs_path = dir.root.join(rel_path);
                let mut file = File::open(&abs_path)
                    .await
                    .with_context(|| format!("cannot open source file {}", abs_path.display()))?;
                let current_len = file.metadata().await?.len();
                if current_len != *size {
                    bail!(
                        "source file {} changed while transferring",
                        abs_path.display()
                    );
                }

                write_frame(
                    send,
                    &DirFrame::FileHeader {
                        path: rel_path.clone(),
                        size: *size,
                        executable: *executable,
                    },
                    timeouts.io(),
                )
                .await?;

                let mut file_hasher = blake3::Hasher::new();
                let mut file_sent = 0u64;
                while file_sent < *size {
                    let to_read = ((*size - file_sent).min(CHUNK as u64)) as usize;
                    let n = file
                        .read(&mut buf[..to_read])
                        .await
                        .context("reading file chunk")?;
                    if n == 0 {
                        bail!("source file {} truncated unexpectedly", abs_path.display());
                    }
                    file_hasher.update(&buf[..n]);
                    tokio::time::timeout(timeouts.io(), send.write_all(&buf[..n]))
                        .await
                        .context("sending stalled")??;
                    file_sent += n as u64;
                    sent += n as u64;
                    progress.update(sent);

                    let elapsed = window_start.elapsed();
                    if elapsed >= timeouts.io() {
                        let bytes_in_window = sent - window_start_sent;
                        let remaining_expected = dir.total_size - window_start_sent;
                        let min_required = MIN_THROUGHPUT_PER_WINDOW.min(remaining_expected);
                        if bytes_in_window < min_required && sent < dir.total_size {
                            bail!(
                                "transfer rate too slow; aborted to prevent connection starvation"
                            );
                        }
                        window_start = Instant::now();
                        window_start_sent = sent;
                    }
                }

                let file_hash = file_hasher.finalize().to_hex().to_string();
                tree_hasher.update(b"F\0");
                tree_hasher.update(&(rel_path.len() as u32).to_be_bytes());
                tree_hasher.update(rel_path.as_bytes());
                tree_hasher.update(&size.to_be_bytes());
                tree_hasher.update(if *executable { &[1u8] } else { &[0u8] });
                tree_hasher.update(file_hash.as_bytes());

                write_frame(send, &DirFrame::FileEnd { hash: file_hash }, timeouts.io()).await?;
            }
        }
    }

    let root_hash = tree_hasher.finalize().to_hex().to_string();
    write_frame(
        send,
        &DirFrame::EndDir {
            root_hash: root_hash.clone(),
        },
        timeouts.io(),
    )
    .await?;
    send.finish()?;

    events(Event::AwaitingReceipt);
    let receipt: VerifiedReceipt = read_frame(recv, timeouts.io()).await
        .context("delivery unconfirmed: receiver did not acknowledge a verified save; check the destination before retrying")?;
    expect_eof(recv, timeouts.io()).await?;

    if !receipt.is_directory
        || receipt.size != dir.total_size
        || receipt.hash != root_hash
        || receipt.name.is_empty()
        || receipt.name.len() > 240
        || receipt.name.contains(['/', '\\'])
        || receipt.name == "."
        || receipt.name == ".."
        || receipt.name.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '\u{200e}'
                        | '\u{200f}'
                        | '\u{061c}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
    {
        bail!("invalid delivery receipt; transfer not confirmed");
    }

    Ok(TransferReceipt {
        name: receipt.name,
        size: receipt.size,
        hash: receipt.hash,
        saved_to: None,
        is_directory: true,
    })
}

async fn receiver_protocol(
    options: &ReceiveOptions,
    send: &mut SendStream,
    recv: &mut RecvStream,
    binding: &[u8; 32],
    events: &EventHandler,
) -> Result<TransferReceipt> {
    events(Event::Authenticating);
    tokio::time::timeout(
        Duration::from_secs(options.timeouts.pake),
        pake::receiver_handshake(options.code.expose(), send, recv, binding),
    )
    .await
    .context("authentication timed out; ask the sender for a fresh code")?
    .context("authentication failed; check the code and ask the sender to retry")?;
    tokio::time::timeout(options.timeouts.io(), send.write_all(b"GET"))
        .await
        .context("request stalled")??;
    let meta: FileMeta = read_frame(recv, options.timeouts.io()).await?;
    if meta.size > options.max_size {
        bail!(
            "{} exceeds the receive limit of {} bytes; use --max-size to change it",
            if meta.is_directory {
                "directory"
            } else {
                "file"
            },
            options.max_size
        );
    }

    if meta.is_directory {
        receiver_dir_protocol(options, &meta, send, recv, events).await
    } else {
        receiver_file_protocol(options, &meta, send, recv, events).await
    }
}

async fn receiver_file_protocol(
    options: &ReceiveOptions,
    meta: &FileMeta,
    send: &mut SendStream,
    recv: &mut RecvStream,
    events: &EventHandler,
) -> Result<TransferReceipt> {
    if meta.hash.len() != 64
        || !meta
            .hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("invalid file checksum in metadata");
    }
    tokio::fs::create_dir_all(&options.directory)
        .await
        .context("creating destination directory")?;
    let directory = tokio::fs::canonicalize(&options.directory)
        .await
        .context("resolving destination directory")?;
    let (mut resumable, mut resume_offset) = ResumableFile::open_or_resume(
        &directory,
        &meta.name,
        meta.size,
        &meta.hash,
        options.resume,
    )?;

    if resume_offset > 0 && resume_offset % CHECKPOINT_INTERVAL != 0 {
        resumable.discard_checkpoint();
        resume_offset = 0;
    }

    if resume_offset > 0 {
        events(Event::Resuming {
            offset: resume_offset,
            total: meta.size,
        });
        write_frame(
            send,
            &TransferRequest::Resume {
                offset: resume_offset,
            },
            options.timeouts.io(),
        )
        .await?;
    } else {
        write_frame(send, &TransferRequest::Full, options.timeouts.io()).await?;
    }

    let resp: TransferResponse = read_frame(recv, options.timeouts.io()).await?;
    let start_offset = match resp {
        TransferResponse::Accepted { start_offset } => {
            if start_offset != resume_offset {
                bail!(
                    "sender offset mismatch: requested {resume_offset}, sender accepted {start_offset}"
                );
            }
            start_offset
        }
        TransferResponse::Rejected { reason } => {
            resumable.discard_checkpoint();
            bail!("sender rejected transfer request: {reason}");
        }
    };

    let mut received = start_offset;
    let mut last_checkpoint = start_offset;
    let mut progress = Progress::new(start_offset, meta.size, events);
    progress.update(received);
    let mut window_start = Instant::now();
    let mut window_start_received = start_offset;
    while received < meta.size {
        let limit = ((meta.size - received).min(CHUNK as u64)) as usize;
        let chunk = tokio::time::timeout(options.timeouts.io(), recv.read_chunk(limit, true))
            .await
            .context("receiving stalled; temporary file removed")??
            .context("sender disconnected before all bytes arrived")?;
        if chunk.bytes.is_empty() {
            continue;
        }
        resumable.write(&chunk.bytes)?;
        received += chunk.bytes.len() as u64;
        progress.update(received);

        if options.resume {
            let aligned_checkpoint = (received / CHECKPOINT_INTERVAL) * CHECKPOINT_INTERVAL;
            if aligned_checkpoint > last_checkpoint && received < meta.size {
                resumable.checkpoint(aligned_checkpoint)?;
                last_checkpoint = aligned_checkpoint;
                progress.force_update(received);
            }
        }

        let elapsed = window_start.elapsed();
        if elapsed >= options.timeouts.io() {
            let bytes_in_window = received - window_start_received;
            let remaining_expected = meta.size - window_start_received;
            let min_required = MIN_THROUGHPUT_PER_WINDOW.min(remaining_expected);
            if bytes_in_window < min_required && received < meta.size {
                bail!("transfer rate too slow; aborted to prevent connection starvation");
            }
            window_start = Instant::now();
            window_start_received = received;
        }
    }
    expect_eof(recv, options.timeouts.io())
        .await
        .context("sender supplied extra data or did not finish")?;
    events(Event::Verifying);

    let hash_for_commit = meta.hash.clone();
    let published = tokio::task::spawn_blocking(move || resumable.commit(&hash_for_commit))
        .await
        .context("file publication task panicked")??;
    if let Some(warning) = published.sync_warning {
        events(Event::Warning { message: warning });
    }
    let path = published.path;
    let name = path
        .file_name()
        .context("saved path has no filename")?
        .to_string_lossy()
        .into_owned();
    let receipt = VerifiedReceipt {
        name: name.clone(),
        size: meta.size,
        hash: meta.hash.clone(),
        is_directory: false,
    };
    let ack = async {
        write_frame(send, &receipt, options.timeouts.io()).await?;
        send.finish()?;
        let stopped = tokio::time::timeout(options.timeouts.io(), send.stopped())
            .await
            .context("receipt acknowledgement timed out")??;
        if stopped.is_some() {
            bail!("sender rejected the receipt");
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(err) = ack {
        events(Event::Warning {
            message: format!(
                "file saved at {}, but sender confirmation is uncertain: {err:#}",
                path.display()
            ),
        });
    }
    Ok(TransferReceipt {
        name,
        size: meta.size,
        hash: meta.hash.clone(),
        saved_to: Some(path),
        is_directory: false,
    })
}

async fn receiver_dir_protocol(
    options: &ReceiveOptions,
    meta: &FileMeta,
    send: &mut SendStream,
    recv: &mut RecvStream,
    events: &EventHandler,
) -> Result<TransferReceipt> {
    let expected_entries = meta
        .entries_count
        .ok_or_else(|| anyhow!("directory metadata missing entries_count"))?;
    if expected_entries > 100_000 {
        bail!("directory exceeds maximum entries limit (100,000)");
    }
    tokio::fs::create_dir_all(&options.directory)
        .await
        .context("creating destination directory")?;
    let directory = tokio::fs::canonicalize(&options.directory)
        .await
        .context("resolving destination directory")?;

    let pending_dir = PendingDirectory::create(&directory)?;
    let mut tree_hasher = blake3::Hasher::new();
    tree_hasher.update(b"WISP_DIR_V1\0");

    let mut received = 0u64;
    let mut received_entries = 0u64;
    let mut last_path: Option<String> = None;
    let mut progress = Progress::new(0, meta.size, events);
    let mut window_start = Instant::now();
    let mut window_start_received = 0u64;

    loop {
        let frame: DirFrame = read_frame(recv, options.timeouts.io()).await?;
        match frame {
            DirFrame::Dir { path } => {
                received_entries += 1;
                if received_entries > 100_000 || received_entries > expected_entries {
                    bail!(
                        "directory entries exceed declared entries count ({}) or safety cap (100,000)",
                        expected_entries
                    );
                }
                if let Some(ref prev) = last_path {
                    if &path <= prev {
                        bail!("directory stream framing error: non-monotonic path ordering");
                    }
                }
                last_path = Some(path.clone());

                let safe_path = sanitize_relative_path(&path)?;
                pending_dir.create_subdir(&safe_path)?;
                tree_hasher.update(b"D\0");
                tree_hasher.update(&(path.len() as u32).to_be_bytes());
                tree_hasher.update(path.as_bytes());
            }
            DirFrame::FileHeader {
                path,
                size,
                executable,
            } => {
                received_entries += 1;
                if received_entries > 100_000 || received_entries > expected_entries {
                    bail!(
                        "directory entries exceed declared entries count ({}) or safety cap (100,000)",
                        expected_entries
                    );
                }
                if let Some(ref prev) = last_path {
                    if &path <= prev {
                        bail!("directory stream framing error: non-monotonic path ordering");
                    }
                }
                last_path = Some(path.clone());

                let safe_path = sanitize_relative_path(&path)?;
                let new_total = received
                    .checked_add(size)
                    .ok_or_else(|| anyhow!("received byte count overflow"))?;
                if new_total > meta.size {
                    bail!("directory files exceed declared total size");
                }
                let mut out_file = pending_dir.open_file(&safe_path, executable)?;
                let mut file_hasher = blake3::Hasher::new();
                let mut file_received = 0u64;

                while file_received < size {
                    let limit = ((size - file_received).min(CHUNK as u64)) as usize;
                    let chunk =
                        tokio::time::timeout(options.timeouts.io(), recv.read_chunk(limit, true))
                            .await
                            .context("receiving stalled; temporary file removed")??
                            .context("sender disconnected before all bytes arrived")?;
                    if chunk.bytes.is_empty() {
                        continue;
                    }
                    file_hasher.update(&chunk.bytes);
                    use std::io::Write;
                    out_file
                        .write_all(&chunk.bytes)
                        .context("writing received file chunk")?;
                    file_received += chunk.bytes.len() as u64;
                    received += chunk.bytes.len() as u64;
                    progress.update(received);

                    let elapsed = window_start.elapsed();
                    if elapsed >= options.timeouts.io() {
                        let bytes_in_window = received - window_start_received;
                        let remaining_expected = meta.size - window_start_received;
                        let min_required = MIN_THROUGHPUT_PER_WINDOW.min(remaining_expected);
                        if bytes_in_window < min_required && received < meta.size {
                            bail!(
                                "transfer rate too slow; aborted to prevent connection starvation"
                            );
                        }
                        window_start = Instant::now();
                        window_start_received = received;
                    }
                }

                out_file.sync_data().context("syncing received file")?;
                drop(out_file);

                let end: DirFrame = read_frame(recv, options.timeouts.io()).await?;
                let DirFrame::FileEnd {
                    hash: expected_file_hash,
                } = end
                else {
                    bail!("protocol error: expected FileEnd frame");
                };

                let computed_file_hash = file_hasher.finalize().to_hex().to_string();
                if computed_file_hash != expected_file_hash {
                    bail!("file integrity check failed for {}", safe_path.display());
                }

                tree_hasher.update(b"F\0");
                tree_hasher.update(&(path.len() as u32).to_be_bytes());
                tree_hasher.update(path.as_bytes());
                tree_hasher.update(&size.to_be_bytes());
                tree_hasher.update(if executable { &[1u8] } else { &[0u8] });
                tree_hasher.update(computed_file_hash.as_bytes());
            }
            DirFrame::FileEnd { .. } => {
                bail!("unexpected FileEnd frame outside file transfer");
            }
            DirFrame::EndDir { root_hash } => {
                if received != meta.size {
                    bail!(
                        "directory received bytes ({}) do not match declared size ({})",
                        received,
                        meta.size
                    );
                }
                if received_entries != expected_entries {
                    bail!(
                        "directory received entries ({}) do not match declared entries count ({})",
                        received_entries,
                        expected_entries
                    );
                }
                expect_eof(recv, options.timeouts.io()).await?;
                events(Event::Verifying);
                let computed_root_hash = tree_hasher.finalize().to_hex().to_string();
                if computed_root_hash != root_hash {
                    bail!("directory integrity verification failed");
                }
                let name_for_commit = meta.name.clone();
                let published =
                    tokio::task::spawn_blocking(move || pending_dir.commit(&name_for_commit))
                        .await
                        .context("directory publication task panicked")??;
                if let Some(warning) = published.sync_warning {
                    events(Event::Warning { message: warning });
                }
                let path = published.path;
                let name = path
                    .file_name()
                    .context("saved path has no filename")?
                    .to_string_lossy()
                    .into_owned();
                let receipt = VerifiedReceipt {
                    name: name.clone(),
                    size: received,
                    hash: root_hash.clone(),
                    is_directory: true,
                };
                let ack = async {
                    write_frame(send, &receipt, options.timeouts.io()).await?;
                    send.finish()?;
                    let stopped = tokio::time::timeout(options.timeouts.io(), send.stopped())
                        .await
                        .context("receipt acknowledgement timed out")??;
                    if stopped.is_some() {
                        bail!("sender rejected the receipt");
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(err) = ack {
                    events(Event::Warning {
                        message: format!(
                            "directory saved at {}, but sender confirmation is uncertain: {err:#}",
                            path.display()
                        ),
                    });
                }
                return Ok(TransferReceipt {
                    name,
                    size: received,
                    hash: root_hash,
                    saved_to: Some(path),
                    is_directory: true,
                });
            }
        }
    }
}

async fn write_frame<T: Serialize>(
    send: &mut SendStream,
    value: &T,
    timeout: Duration,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        bail!("protocol frame too large");
    }
    tokio::time::timeout(timeout, async {
        send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
        send.write_all(&bytes).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("protocol write timed out")??;
    Ok(())
}
async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream, timeout: Duration) -> Result<T> {
    tokio::time::timeout(timeout, async {
        let mut len = [0; 4];
        recv.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_FRAME {
            bail!("invalid protocol frame length: {len}");
        }
        if len <= 4096 {
            let mut stack_buf = [0u8; 4096];
            recv.read_exact(&mut stack_buf[..len]).await?;
            serde_json::from_slice(&stack_buf[..len]).context("invalid protocol message")
        } else {
            let mut bytes = vec![0; len];
            recv.read_exact(&mut bytes).await?;
            serde_json::from_slice(&bytes).context("invalid protocol message")
        }
    })
    .await
    .context("protocol read timed out")?
}
async fn expect_eof(recv: &mut RecvStream, timeout: Duration) -> Result<()> {
    if tokio::time::timeout(timeout, recv.read_chunk(1, true))
        .await
        .context("stream finish timed out")??
        .is_some()
    {
        bail!("unexpected trailing bytes");
    }
    Ok(())
}

struct Progress<'a> {
    total: u64,
    last: Instant,
    events: &'a EventHandler,
}
impl<'a> Progress<'a> {
    fn new(initial: u64, total: u64, events: &'a EventHandler) -> Self {
        events(Event::Progress {
            transferred: initial,
            total,
        });
        Self {
            total,
            last: Instant::now(),
            events,
        }
    }
    fn update(&mut self, transferred: u64) {
        if transferred == self.total || self.last.elapsed() >= Duration::from_millis(100) {
            (self.events)(Event::Progress {
                transferred,
                total: self.total,
            });
            self.last = Instant::now();
        }
    }
    fn force_update(&mut self, transferred: u64) {
        (self.events)(Event::Progress {
            transferred,
            total: self.total,
        });
        self.last = Instant::now();
    }
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
