//! The Wisp transfer protocol (WSP/1), Phase 3.
//!
//! Discovery:
//!   LAN  — mDNS with code commitment + TLS fingerprint (no relay needed)
//!   WAN  — HTTP rendezvous via a `wisp-relay` server (--relay <host:port>)
//!
//! Wire format over a single QUIC bidirectional stream (same for LAN and WAN):
//!
//!   [SPAKE2 + confirmation handshake — see pake.rs]
//!   receiver → sender : "GET"  then stream finish
//!   sender   → receiver : [u32 BE meta_len][meta_json][raw file bytes]
//!
//! Integrity: BLAKE3 verify-before-rename (`.wisp-part` → final name).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use quinn::Endpoint;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{discovery, pake, relay, transport};

const CHUNK: usize = 64 * 1024;
const MAX_META: usize = 64 * 1024;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);

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
) -> Result<()> {
    if !path.is_file() {
        return Err(anyhow!("not a regular file: {}", path.display()));
    }

    let name = sanitize(&display_name.unwrap_or_else(|| {
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into())
    }));

    eprintln!("  computing BLAKE3 checksum…");
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
        let host = relay::strip_scheme(url);
        let ch = crate::code_commitment(&code);
        let observed_ip = relay::announce(host, &ch, &fp_hex, port)
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
    eprintln!("  ↘ peer connected from {}", conn.remote_address());

    let (mut send, mut recv) = conn.accept_bi().await.context("accepting stream")?;

    pake::sender_handshake(&code, &mut send, &mut recv)
        .await
        .context("PAKE handshake failed")?;

    let _ = recv.read_to_end(16).await;

    let meta = FileMeta {
        name: name.clone(),
        size,
        hash: hash.clone(),
    };
    let json = serde_json::to_vec(&meta)?;
    send.write_all(&(json.len() as u32).to_be_bytes()).await?;
    send.write_all(&json).await?;

    let pb = progress(size, "  ↗ sending  ");
    let mut file = File::open(&path).await?;
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u64;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n]).await?;
        sent += n as u64;
        pb.set_position(sent);
    }
    send.finish().context("finishing stream")?;
    pb.finish_and_clear();

    conn.closed().await;
    println!("  ✓ delivered {name} ({}) — wisp gone.", human(size));
    Ok(())
}

/// Receive a file by its pairing code. Pass `relay_url` for WAN mode.
pub async fn receive_file(code: String, dir: PathBuf, relay_url: Option<String>) -> Result<()> {
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("creating output directory {}", dir.display()))?;

    // Discovery: LAN (mDNS) or WAN (relay).
    let (peer_ip, peer_port, fingerprint) = if let Some(ref url) = relay_url {
        let host = relay::strip_scheme(url);
        println!("  querying relay for `{code}`…");
        let (ip, port, fp) = relay::find_wan(host, &code).await.context("relay lookup")?;
        (ip, port, fp)
    } else {
        println!("  searching for `{code}` on the local network…");
        let resolved = tokio::task::spawn_blocking({
            let code = code.clone();
            move || discovery::find(&code, DISCOVERY_TIMEOUT)
        })
        .await
        .context("discovery task")??;
        (resolved.addr, resolved.port, resolved.fingerprint)
    };

    let client_config = transport::make_client_config(fingerprint)?;
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .context("starting QUIC client")?;
    endpoint.set_default_client_config(client_config);

    let server_addr = SocketAddr::new(IpAddr::V4(peer_ip), peer_port);
    let conn = endpoint
        .connect(server_addr, "wisp")
        .context("initiating connection")?
        .await
        .context("connecting to sender (fingerprint pinned)")?;

    let (mut send, mut recv) = conn.open_bi().await.context("opening stream")?;

    pake::receiver_handshake(&code, &mut send, &mut recv)
        .await
        .context("PAKE handshake failed")?;

    send.write_all(b"GET").await?;
    send.finish().context("finishing request")?;

    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("reading metadata length")?;
    let meta_len = u32::from_be_bytes(len_buf) as usize;
    if meta_len == 0 || meta_len > MAX_META {
        return Err(anyhow!("invalid metadata length: {meta_len}"));
    }
    let mut meta_buf = vec![0u8; meta_len];
    recv.read_exact(&mut meta_buf)
        .await
        .context("reading metadata")?;
    let meta: FileMeta = serde_json::from_slice(&meta_buf).context("parsing metadata")?;

    let safe = sanitize(&meta.name);
    let final_path = unique_path(&dir, &safe);
    let part_path = with_part_suffix(&final_path);

    let pb = progress(meta.size, "  ↘ receiving");
    let mut file = File::create(&part_path)
        .await
        .with_context(|| format!("creating {}", part_path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut received = 0u64;

    while received < meta.size {
        match recv.read(&mut buf).await.context("reading file data")? {
            Some(0) | None => break,
            Some(n) => {
                hasher.update(&buf[..n]);
                file.write_all(&buf[..n]).await?;
                received += n as u64;
                pb.set_position(received);
            }
        }
    }
    file.flush().await?;
    pb.finish_and_clear();

    let actual = hasher.finalize().to_hex().to_string();
    if received != meta.size || actual != meta.hash {
        let _ = tokio::fs::remove_file(&part_path).await;
        return Err(anyhow!(
            "integrity check FAILED — corrupt or tampered transfer (discarded {} of {} bytes)",
            received,
            meta.size
        ));
    }

    tokio::fs::rename(&part_path, &final_path)
        .await
        .context("finalizing file")?;

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    println!(
        "  ✓ verified · {} · saved to {}",
        human(meta.size),
        final_path.display()
    );
    Ok(())
}

// ===== helpers =====

async fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), size))
}

fn sanitize(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('.').to_string();
    if trimmed.is_empty() {
        "file".into()
    } else {
        trimmed.chars().take(200).collect()
    }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let mut candidate = dir.join(name);
    let mut i = 1;
    while candidate.exists() {
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
        IpAddr::V6(_) => Err(anyhow!("no IPv4 address found on this host")),
    }
}

fn print_send_banner_lan(code: &str, name: &str, size: u64, ip: Ipv4Addr, port: u16, hash: &str) {
    println!();
    println!("  ✦ wisp ready  (LAN)");
    println!("    file   {name} ({})", human(size));
    println!("    from   {ip}:{port}");
    println!("    blake3 {}…", &hash[..hash.len().min(16)]);
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
    observed_ip: Ipv4Addr,
    port: u16,
    hash: &str,
    relay_url: &str,
) {
    println!();
    println!("  ✦ wisp ready  (WAN via relay)");
    println!("    file   {name} ({})", human(size));
    println!("    public {observed_ip}:{port}");
    println!("    relay  {relay_url}");
    println!("    blake3 {}…", &hash[..hash.len().min(16)]);
    println!();
    println!("    on the other machine, run:");
    println!("      wisp recv --relay {relay_url} {code}");
    println!();
    println!("  waiting for a receiver…");
}
