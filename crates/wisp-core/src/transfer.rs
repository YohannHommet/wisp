//! The Wisp transfer protocol (WSP/1), Phase 3.
//!
//! Discovery:
//!   LAN  — mDNS with code commitment + TLS fingerprint (no relay needed)
//!   WAN  — HTTP rendezvous via a `wisp-relay` server (--relay <host:port>)
//!
//! Wire format over a single QUIC bidirectional stream (same for LAN and WAN):
//!
//!   [SPAKE2 + confirmation handshake — see pake.rs]
//!   receiver → sender : any bytes then stream finish  (synchronization gate)
//!   sender   → receiver : [u32 BE meta_len][meta_json][raw file bytes]
//!
//! Integrity (receiver side): BLAKE3 hash verified before `.wisp-part` is
//! renamed to its final name. The sender does not perform this check — it
//! trusts the pre-computed hash it advertises.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context};
use crate::error::{Error, Result};
use crate::{discovery, pake, relay, transport};
use indicatif::{ProgressBar, ProgressStyle};
use quinn::{Endpoint, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type ProgressCallback = std::sync::Arc<dyn Fn(u64, u64) + Send + Sync + 'static>;

const CHUNK: usize = 64 * 1024;
const MAX_META: usize = 64 * 1024;
const MAX_FILE_SIZE: u64 = 1_099_511_627_776; // 1 TiB
const QUIC_TIMEOUT: Duration = Duration::from_secs(30);
const POST_SEND_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
struct FileMeta {
    name: String,
    size: u64,
    hash: String,
}

/// Send a file. Pass `relay_url` (e.g. `"http://relay.example.com:7777"`) to
/// reach a receiver on a different network; omit for LAN-only (mDNS).
pub async fn send_file(
    path: PathBuf,
    display_name: Option<String>,
    relay_url: Option<String>,
    progress_cb: Option<ProgressCallback>,
) -> Result<()> {
    if !path.is_file() {
        return Err(Error::InvalidFile(path));
    }

    let config = crate::config::Config::load().unwrap_or_default();
    let timeouts = config.resolve_timeouts();

    let name = sanitize(&display_name.unwrap_or_else(|| {
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into())
    }));

    eprintln!("  \x1b[90mcomputing BLAKE3 checksum…\x1b[0m");
    let (hash, size) = hash_file(&path).await?;

    let setup = transport::make_server_config()?;
    let fingerprint = setup.fingerprint;
    let endpoint = Endpoint::server(
        setup.config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    )
    .context("starting QUIC server")?;
    let port = endpoint.local_addr()?.port();
    let fp_hex = hex::encode(fingerprint);
    let code = crate::code::generate();

    // Discovery: LAN (mDNS) or WAN (relay).
    // _advert keeps the mDNS registration alive until we drop it after the transfer.
    let _advert;
    if let Some(ref url) = relay_url {
        let ch = crate::code_commitment(&code);
        let observed_ip = relay::announce(url, &ch, &fp_hex, port)
            .await
            .context("relay announce")?;
        _advert = None::<discovery::Advert>;
        print_send_banner_wan(&code, &name, size, observed_ip, port, &hash, url);
    } else {
        let ip = local_ipv4()?;
        _advert = Some(discovery::advertise(&code, ip, port, &fp_hex)?);
        print_send_banner_lan(&code, &name, size, ip, port, &hash);
    }

    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow!("listener closed before a peer connected"))?;
    let conn = incoming.await.context("accepting connection")?;
    eprintln!("  \x1b[32m↘ peer connected from {}\x1b[0m", conn.remote_address());

    let (mut send, mut recv) = conn.accept_bi().await.context("accepting stream")?;

    let mut tls_unique = [0u8; 32];
    conn.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[])
        .map_err(|e| anyhow!("failed to export TLS channel binding: {:?}", e))?;

    sender_protocol(&code, &path, &name, size, &hash, &mut send, &mut recv, &tls_unique, &timeouts, &progress_cb).await?;

    // Give the receiver up to POST_SEND_TIMEOUT to close the connection gracefully.
    // If it crashes or stalls we still move on and report success — the file was sent.
    tokio::time::timeout(POST_SEND_TIMEOUT, conn.closed()).await.ok();
    println!("  \x1b[32m✓ delivered\x1b[0m {name} ({}) — wisp gone.", human(size));
    Ok(())
}

/// Receive a file by its pairing code. Pass `relay_url` for WAN mode.
pub async fn receive_file(
    code: String,
    dir: PathBuf,
    relay_url: Option<String>,
    progress_cb: Option<ProgressCallback>,
) -> Result<()> {
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("creating output directory {}", dir.display()))?;

    let config = crate::config::Config::load().unwrap_or_default();
    let timeouts = config.resolve_timeouts();

    // Discovery: LAN (mDNS) or WAN (relay).
    let (peer_ip, peer_port, fingerprint) = if let Some(ref url) = relay_url {
        println!("  \x1b[90mquerying relay for `{code}`…\x1b[0m");
        let (ip, port, fp) = relay::find_wan(url, &code).await.context("relay lookup")?;
        (ip, port, fp)
    } else {
        println!("  \x1b[90msearching for `{code}` on the local network…\x1b[0m");
        let resolved = tokio::task::spawn_blocking({
            let code = code.clone();
            let timeout = timeouts.discovery;
            move || discovery::find(&code, timeout)
        })
        .await
        .context("discovery task")??;
        (IpAddr::V4(resolved.addr), resolved.port, resolved.fingerprint)
    };

    let client_config = transport::make_client_config(fingerprint)?;
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .context("starting QUIC client")?;
    endpoint.set_default_client_config(client_config);

    let server_addr = SocketAddr::new(peer_ip, peer_port);
    let connecting = endpoint
        .connect(server_addr, "wisp")
        .context("initiating connection")?;
    let conn = tokio::time::timeout(QUIC_TIMEOUT, connecting)
        .await
        .context("connection to sender timed out")?
        .context("connecting to sender (fingerprint pinned)")?;

    let (mut send, mut recv) = tokio::time::timeout(QUIC_TIMEOUT, conn.open_bi())
        .await
        .context("timed out opening QUIC stream")?
        .context("opening stream")?;

    let mut tls_unique = [0u8; 32];
    conn.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[])
        .map_err(|e| anyhow!("failed to export TLS channel binding: {:?}", e))?;

    let (final_path, size) =
        receiver_protocol(&code, &dir, &mut send, &mut recv, &tls_unique, &timeouts, &progress_cb).await?;

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    println!(
        "  \x1b[32m✓ verified\x1b[0m · {} · saved to \x1b[1;36m{}\x1b[0m",
        human(size),
        final_path.display()
    );
    Ok(())
}

// ===== stream-level protocol (decoupled from discovery and QUIC setup) =====

/// Run the sender side of the protocol on an already-established QUIC stream.
///
/// Performs PAKE, waits for the receiver's ready signal, then streams the file.
async fn sender_protocol(
    code: &str,
    path: &Path,
    name: &str,
    size: u64,
    hash: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tls_unique: &[u8; 32],
    timeouts: &crate::config::ResolvedTimeouts,
    progress_cb: &Option<ProgressCallback>,
) -> Result<()> {
    tokio::time::timeout(timeouts.pake, pake::sender_handshake(code, send, recv, tls_unique))
        .await
        .context("PAKE handshake timed out")?
        .context("PAKE handshake failed")?;

    tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(16))
        .await
        .context("receiver ready signal timed out")?
        .context("waiting for receiver ready signal")?;

    let meta = FileMeta {
        name: name.to_string(),
        size,
        hash: hash.to_string(),
    };
    let json = serde_json::to_vec(&meta)?;
    tokio::time::timeout(timeouts.block_transfer, async {
        send.write_all(&(json.len() as u32).to_be_bytes()).await?;
        send.write_all(&json).await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("metadata write stalled")??;

    let pb = if progress_cb.is_none() {
        Some(progress(size, "  ↗ sending  "))
    } else {
        None
    };

    let file = File::open(path).await?;
    let mut file = tokio::io::BufReader::with_capacity(256 * 1024, file);
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u64;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        tokio::time::timeout(timeouts.block_transfer, send.write_all(&buf[..n]))
            .await
            .context("chunk write stalled")?
            .context("writing chunk")?;
        sent += n as u64;
        if let Some(ref p) = pb {
            p.set_position(sent);
        }
        if let Some(ref cb) = progress_cb {
            cb(sent, size);
        }
    }
    send.finish().context("finishing stream")?;
    if let Some(ref p) = pb {
        p.finish_and_clear();
    }
    Ok(())
}

/// Run the receiver side of the protocol on an already-established QUIC stream.
///
/// Performs PAKE, sends the ready signal, receives and verifies the file.
/// Returns `(final_path, file_size)` on success.
async fn receiver_protocol(
    code: &str,
    dir: &Path,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tls_unique: &[u8; 32],
    timeouts: &crate::config::ResolvedTimeouts,
    progress_cb: &Option<ProgressCallback>,
) -> Result<(PathBuf, u64)> {
    tokio::time::timeout(timeouts.pake, pake::receiver_handshake(code, send, recv, tls_unique))
        .await
        .context("PAKE handshake timed out")?
        .context("PAKE handshake failed")?;

    send.write_all(b"GET").await?;
    send.finish().context("finishing request")?;

    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeouts.block_transfer, recv.read_exact(&mut len_buf))
        .await
        .context("metadata length read stalled")?
        .context("reading metadata length")?;
    let meta_len = u32::from_be_bytes(len_buf) as usize;
    if meta_len == 0 || meta_len > MAX_META {
        return Err(Error::Protocol(format!("invalid metadata length: {meta_len}")));
    }
    let mut meta_buf = vec![0u8; meta_len];
    tokio::time::timeout(timeouts.block_transfer, recv.read_exact(&mut meta_buf))
        .await
        .context("metadata read stalled")?
        .context("reading metadata")?;
    let meta: FileMeta = serde_json::from_slice(&meta_buf).context("parsing metadata")?;

    if meta.size > MAX_FILE_SIZE {
        return Err(Error::Protocol(format!(
            "sender claims file size {} — refusing files over 1 TiB",
            human(meta.size)
        )));
    }

    let safe = sanitize(&meta.name);
    let final_path = unique_path(dir, &safe).await;
    let part_path = with_part_suffix(&final_path);
    let file_size = meta.size;

    let mut guard = PartFileGuard {
        path: part_path.clone(),
        active: true,
    };

    // Wrap body receive in an async block for a single cleanup site:
    // on any error between File::create and rename, delete the part file.
    let outcome: Result<()> = async {
        let pb = if progress_cb.is_none() {
            Some(progress(meta.size, "  ↘ receiving"))
        } else {
            None
        };
        let file = File::create(&part_path)
            .await
            .with_context(|| format!("creating {}", part_path.display()))?;
        let mut file = tokio::io::BufWriter::with_capacity(256 * 1024, file);
        let mut hasher = blake3::Hasher::new();
        let mut received = 0u64;

        while received < meta.size {
            let chunk_opt = tokio::time::timeout(timeouts.block_transfer, recv.read_chunk(CHUNK, true))
                .await
                .context("stalled: no data received for 30 s")?
                .context("reading file data")?;
            match chunk_opt {
                None => break,
                Some(chunk) => {
                    let n = chunk.bytes.len();
                    if n == 0 {
                        break;
                    }
                    hasher.update(&chunk.bytes);
                    file.write_all(&chunk.bytes).await?;
                    received += n as u64;
                    if let Some(ref p) = pb {
                        p.set_position(received);
                    }
                    if let Some(ref cb) = progress_cb {
                        cb(received, meta.size);
                    }
                }
            }
        }
        file.flush().await?;
        if let Some(ref p) = pb {
            p.finish_and_clear();
        }

        let actual = hasher.finalize().to_hex().to_string();
        if received != meta.size || actual != meta.hash {
            return Err(Error::Integrity {
                received,
                expected: meta.size,
            });
        }

        tokio::fs::rename(&part_path, &final_path)
            .await
            .context("finalizing file")?;

        Ok(())
    }
    .await;

    if let Err(e) = outcome {
        return Err(e);
    }

    guard.active = false;

    Ok((final_path, file_size))
}

// ===== helpers =====

async fn hash_file(path: &Path) -> Result<(String, u64)> {
    let path = path.to_owned();
    let res = tokio::task::spawn_blocking(move || {
        use std::fs::File;
        use std::io::Read;
        let mut file = File::open(&path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 128 * 1024]; // 128 KiB buffer for sequential read
        let mut size = 0u64;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        Ok::<_, anyhow::Error>((hasher.finalize().to_hex().to_string(), size))
    })
    .await
    .map_err(|e| Error::Generic(anyhow!("hashing task panicked: {:?}", e)))?;
    res.map_err(Error::from)
}

pub fn sanitize(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let trimmed = base.trim_matches('.').to_string();
    if trimmed.is_empty() {
        return "file".into();
    }
    // 1. Blacklist characters forbidden on Windows and Unix:
    // Windows: \ : * ? " < > |
    // Unix: / \0
    let cleaned: String = trimmed
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0') {
                '_'
            } else {
                c
            }
        })
        .collect();
    
    // 2. Windows reserved file names case-insensitive check (also handles extensions like nul.txt)
    let stem = Path::new(&cleaned)
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_uppercase())
        .unwrap_or_default();
    
    let is_reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    );

    let mut final_name = if is_reserved {
        format!("{cleaned}_")
    } else {
        cleaned
    };

    final_name.truncate(200);
    final_name
}

async fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let mut candidate = dir.join(name);
    let mut i = 1;
    while tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
        let stem = Path::new(name)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into());
        let ext = Path::new(name)
            .extension()
            .map(|s| format!(".{}", s.to_string_lossy()))
            .unwrap_or_default();
        candidate = dir.join(format!("{stem} ({i}){ext}"));
        i += 1;
    }
    candidate
}

fn with_part_suffix(final_path: &Path) -> PathBuf {
    let mut s = final_path.as_os_str().to_owned();
    s.push(".wisp-part");
    PathBuf::from(s)
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

fn progress(size: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(size);
    pb.set_style(
        ProgressStyle::with_template(
            "{msg} {bar:28.cyan/blue} {bytes}/{total_bytes} · {bytes_per_sec} · ETA {eta}",
        )
        .expect("valid progress template")
        .progress_chars("━━ "),
    );
    pb.set_message(msg.to_string());
    pb
}

fn local_ipv4() -> Result<Ipv4Addr> {
    match local_ip_address::local_ip().context("determining local IP")? {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(Error::Discovery("no IPv4 address found on this host".to_string())),
    }
}

fn print_send_banner_lan(code: &str, name: &str, size: u64, ip: Ipv4Addr, port: u16, hash: &str) {
    println!();
    println!("  \x1b[36m✦ wisp ready\x1b[0m  (LAN)");
    println!("    \x1b[1mfile\x1b[0m   {name} ({})", human(size));
    println!("    \x1b[1mfrom\x1b[0m   {ip}:{port}");
    println!("    \x1b[90mblake3 {}…\x1b[0m", &hash[..hash.len().min(16)]);
    println!();
    println!("    on the other machine, run:");
    println!("      wisp recv {code}");
    println!();
    println!("  waiting for a receiver…");
}

fn print_send_banner_wan(
    code: &str,
    name: &str,
    size: u64,
    observed_ip: IpAddr,
    port: u16,
    hash: &str,
    relay_url: &str,
) {
    println!();
    println!("  \x1b[35m✦ wisp ready\x1b[0m  (WAN via relay)");
    println!("    \x1b[1mfile\x1b[0m   {name} ({})", human(size));
    println!("    \x1b[1mpublic\x1b[0m {observed_ip}:{port}");
    println!("    \x1b[1mrelay\x1b[0m  {relay_url}");
    println!("    \x1b[90mblake3 {}…\x1b[0m", &hash[..hash.len().min(16)]);
    println!();
    println!("    on the other machine, run:");
    println!("      wisp recv --relay {relay_url} {code}");
    println!();
    println!("  waiting for a receiver…");
}

// ===== integration tests =====

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Establish a loopback QUIC connection pair.
    async fn quic_loopback() -> (quinn::Connection, quinn::Connection) {
        let setup = crate::transport::make_server_config().unwrap();
        let fingerprint = setup.fingerprint;
        let server_ep = Endpoint::server(
            setup.config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let port = server_ep.local_addr().unwrap().port();

        tokio::join!(
            async {
                let inc = server_ep.accept().await.unwrap();
                inc.await.unwrap()
            },
            async {
                let cfg = crate::transport::make_client_config(fingerprint).unwrap();
                let mut ep =
                    Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                        .unwrap();
                ep.set_default_client_config(cfg);
                ep.connect(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    "wisp",
                )
                .unwrap()
                .await
                .unwrap()
            }
        )
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn transfer_small_file() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let content = b"hello wisp -- integration test payload";
        let src = src_dir.path().join("hello.txt");
        tokio::fs::write(&src, content).await.unwrap();
        let (hash, size) = hash_file(&src).await.unwrap();

        // Keep originals alive so the connection doesn't close when a task finishes.
        let (server_conn, client_conn) = quic_loopback().await;

        let src2 = src.clone();
        let hash2 = hash.clone();
        let sender = tokio::spawn({
            let sc = server_conn.clone();
            async move {
                let (mut s, mut r) = sc.accept_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                sc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                sender_protocol("99-wisp-test", &src2, "hello.txt", size, &hash2, &mut s, &mut r, &tls_unique, &crate::config::ResolvedTimeouts::default(), &None)
                    .await
            }
        });

        let dst = dst_dir.path().to_owned();
        let receiver = tokio::spawn({
            let cc = client_conn.clone();
            async move {
                let (mut s, mut r) = cc.open_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                cc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                receiver_protocol("99-wisp-test", &dst, &mut s, &mut r, &tls_unique, &crate::config::ResolvedTimeouts::default(), &None).await
            }
        });

        sender.await.unwrap().unwrap();
        let (received_path, received_size) = receiver.await.unwrap().unwrap();
        assert_eq!(received_size, content.len() as u64);
        let received = tokio::fs::read(&received_path).await.unwrap();
        assert_eq!(received, content);
    }

    // ── Wrong pairing code ────────────────────────────────────────────────────

    #[tokio::test]
    async fn transfer_wrong_code_fails() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = src_dir.path().join("data.bin");
        tokio::fs::write(&src, b"secret data").await.unwrap();
        let (hash, size) = hash_file(&src).await.unwrap();

        let (server_conn, client_conn) = quic_loopback().await;

        let sender = tokio::spawn({
            let sc = server_conn.clone();
            async move {
                let (mut s, mut r) = sc.accept_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                sc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                sender_protocol("correct-code", &src, "data.bin", size, &hash, &mut s, &mut r, &tls_unique, &crate::config::ResolvedTimeouts::default(), &None)
                    .await
            }
        });

        let dst = dst_dir.path().to_owned();
        let receiver = tokio::spawn({
            let cc = client_conn.clone();
            async move {
                let (mut s, mut r) = cc.open_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                cc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                receiver_protocol("wrong-code", &dst, &mut s, &mut r, &tls_unique, &crate::config::ResolvedTimeouts::default(), &None).await
            }
        });

        let sender_result = sender.await.unwrap();
        let receiver_result = receiver.await.unwrap();
        assert!(sender_result.is_err(), "sender should fail on wrong code");
        assert!(receiver_result.is_err(), "receiver should fail on wrong code");
    }

    // ── Large file integrity ──────────────────────────────────────────────────

    #[tokio::test]
    async fn transfer_large_file_integrity() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        // 2 MiB of deterministic pseudo-random bytes
        let content: Vec<u8> = (0u32..524_288).flat_map(|i| i.to_le_bytes()).collect();
        let src = src_dir.path().join("large.bin");
        tokio::fs::write(&src, &content).await.unwrap();
        let (hash, size) = hash_file(&src).await.unwrap();

        let (server_conn, client_conn) = quic_loopback().await;

        let src2 = src.clone();
        let hash2 = hash.clone();
        let sender = tokio::spawn({
            let sc = server_conn.clone();
            async move {
                let (mut s, mut r) = sc.accept_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                sc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                sender_protocol("42-large-test", &src2, "large.bin", size, &hash2, &mut s, &mut r, &tls_unique, &crate::config::ResolvedTimeouts::default(), &None)
                    .await
            }
        });

        let dst = dst_dir.path().to_owned();
        let receiver = tokio::spawn({
            let cc = client_conn.clone();
            async move {
                let (mut s, mut r) = cc.open_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                cc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                receiver_protocol("42-large-test", &dst, &mut s, &mut r, &tls_unique, &crate::config::ResolvedTimeouts::default(), &None).await
            }
        });

        sender.await.unwrap().unwrap();
        let (received_path, received_size) = receiver.await.unwrap().unwrap();
        assert_eq!(received_size, size);
        let received = tokio::fs::read(&received_path).await.unwrap();
        assert_eq!(
            blake3::hash(&received).to_hex().to_string(),
            hash,
            "BLAKE3 must match after transfer"
        );
    }

    // ── Tampered hash → part file cleaned up ─────────────────────────────────

    #[tokio::test]
    async fn transfer_hash_mismatch_cleans_up_part_file() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let content = b"real file content";
        let src = src_dir.path().join("file.bin");
        tokio::fs::write(&src, content).await.unwrap();
        let (_, size) = hash_file(&src).await.unwrap();

        let (server_conn, client_conn) = quic_loopback().await;

        // Malicious sender: correct PAKE but lying hash in metadata.
        let content_copy = content.to_vec();
        let sender = tokio::spawn({
            let sc = server_conn.clone();
            async move {
                let (mut s, mut r) = sc.accept_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                sc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                tokio::time::timeout(
                    Duration::from_secs(15),
                    pake::sender_handshake("same-code", &mut s, &mut r, &tls_unique),
                )
                .await
                .unwrap()
                .unwrap();
                r.read_to_end(16).await.unwrap();
                let meta = FileMeta {
                    name: "file.bin".to_string(),
                    size,
                    hash: "0".repeat(64), // all-zeros — definitely wrong
                };
                let json = serde_json::to_vec(&meta).unwrap();
                s.write_all(&(json.len() as u32).to_be_bytes()).await.unwrap();
                s.write_all(&json).await.unwrap();
                s.write_all(&content_copy).await.unwrap();
                s.finish().unwrap();
            }
        });

        let dst = dst_dir.path().to_owned();
        let receiver = tokio::spawn({
            let cc = client_conn.clone();
            async move {
                let (mut s, mut r) = cc.open_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                cc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                receiver_protocol("same-code", &dst, &mut s, &mut r, &tls_unique, &crate::config::ResolvedTimeouts::default(), &None).await
            }
        });

        // Sender finishes first; server_conn (outer) keeps connection alive for receiver.
        sender.await.unwrap();
        let result = receiver.await.unwrap();

        assert!(result.is_err(), "integrity check should have failed");
        assert!(
            result.unwrap_err().to_string().contains("integrity check FAILED"),
            "error should mention integrity"
        );

        // The .wisp-part file must be gone
        let leftover: Vec<_> = std::fs::read_dir(dst_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".wisp-part"))
            .collect();
        assert!(leftover.is_empty(), "stale .wisp-part files found: {leftover:?}");
    }

    // ── File-size cap ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn transfer_size_cap_rejects_oversized_claim() {
        let dst_dir = TempDir::new().unwrap();

        let (server_conn, client_conn) = quic_loopback().await;

        // Malicious sender claims a file larger than 1 TiB.
        let sender = tokio::spawn({
            let sc = server_conn.clone();
            async move {
                let (mut s, mut r) = sc.accept_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                sc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                tokio::time::timeout(
                    Duration::from_secs(15),
                    pake::sender_handshake("size-test", &mut s, &mut r, &tls_unique),
                )
                .await
                .unwrap()
                .unwrap();
                r.read_to_end(16).await.unwrap();
                let meta = FileMeta {
                    name: "huge.bin".to_string(),
                    size: MAX_FILE_SIZE + 1,
                    hash: "a".repeat(64),
                };
                let json = serde_json::to_vec(&meta).unwrap();
                s.write_all(&(json.len() as u32).to_be_bytes()).await.unwrap();
                s.write_all(&json).await.unwrap();
                s.finish().unwrap();
            }
        });

        let dst = dst_dir.path().to_owned();
        let receiver = tokio::spawn({
            let cc = client_conn.clone();
            async move {
                let (mut s, mut r) = cc.open_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                cc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                receiver_protocol("size-test", &dst, &mut s, &mut r, &tls_unique, &crate::config::ResolvedTimeouts::default(), &None).await
            }
        });

        sender.await.unwrap();
        let result = receiver.await.unwrap();

        assert!(result.is_err(), "should reject oversized file claim");
        assert!(
            result.unwrap_err().to_string().contains("refusing files over 1 TiB"),
            "error should mention size limit"
        );
    }
}

struct PartFileGuard {
    path: PathBuf,
    active: bool,
}

impl Drop for PartFileGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

