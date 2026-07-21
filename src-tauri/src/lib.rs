use std::collections::HashMap;
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tauri::Emitter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

fn get_friendly_name() -> String {
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = hostname.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "Wisp Peer".to_string())
}

#[derive(Default)]
pub struct TransferManager {
    sessions: Mutex<HashMap<String, CancellationToken>>,
}

struct SessionGuard<'a> {
    sessions: &'a Mutex<HashMap<String, CancellationToken>>,
    session_id: String,
}

impl<'a> Drop for SessionGuard<'a> {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&self.session_id);
        }
    }
}

#[derive(Clone, serde::Serialize)]
struct ProgressPayload {
    transferred: u64,
    total: u64,
}

#[tauri::command]
fn generate_pairing_code() -> String {
    wisp_core::code::generate()
}

#[tauri::command]
fn open_file_dialog() -> Result<String, String> {
    if let Some(file_path) = rfd::FileDialog::new()
        .set_title("Select File to Send")
        .pick_file()
    {
        Ok(file_path.to_string_lossy().into_owned())
    } else {
        Err("File selection cancelled".to_string())
    }
}

#[tauri::command]
fn open_dir_dialog() -> Result<String, String> {
    if let Some(dir_path) = rfd::FileDialog::new()
        .set_title("Select Download Directory")
        .pick_folder()
    {
        Ok(dir_path.to_string_lossy().into_owned())
    } else {
        Err("Directory selection cancelled".to_string())
    }
}

#[tauri::command]
async fn start_send_session(
    window: tauri::Window,
    session_id: String,
    filepath: String,
    relay: Option<String>,
    state: tauri::State<'_, TransferManager>,
) -> Result<(), String> {
    let token = CancellationToken::new();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), token.clone());
    }
    let _guard = SessionGuard {
        sessions: &state.sessions,
        session_id: session_id.clone(),
    };

    let filepath = std::path::PathBuf::from(filepath);
    let window_clone = window.clone();
    
    // Throttled progress callback to prevent IPC overload
    let progress_state = std::sync::Arc::new(std::sync::Mutex::new((
        std::time::Instant::now(),
        0.0f64,
    )));
    
    let progress_state_clone = progress_state.clone();
    let progress_cb = std::sync::Arc::new(move |transferred, total| {
        let percent = if total > 0 {
            (transferred as f64 / total as f64) * 100.0
        } else {
            100.0
        };
        let now = std::time::Instant::now();
        let mut lock = progress_state_clone.lock().unwrap();
        if now.duration_since(lock.0).as_millis() >= 100 || percent - lock.1 >= 1.0 || transferred == total {
            let _ = window_clone.emit("transfer-progress", ProgressPayload { transferred, total });
            lock.0 = now;
            lock.1 = percent;
        }
    });

    let result = tokio::select! {
        res = wisp_core::send_file(filepath, None, relay, Some(progress_cb)) => {
            res.map_err(|e| e.to_string())
        }
        _ = token.cancelled() => {
            Err("Transfer cancelled by user".to_string())
        }
    };

    if let Err(ref e) = result {
        let _ = window.emit("transfer-error", e.clone());
    }

    result
}

#[tauri::command]
async fn start_recv_session(
    window: tauri::Window,
    session_id: String,
    code: String,
    download_dir: String,
    relay: Option<String>,
    state: tauri::State<'_, TransferManager>,
) -> Result<(), String> {
    let token = CancellationToken::new();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), token.clone());
    }
    let _guard = SessionGuard {
        sessions: &state.sessions,
        session_id: session_id.clone(),
    };

    let download_dir = std::path::PathBuf::from(download_dir);
    let window_clone = window.clone();
    
    // Throttled progress callback to prevent IPC overload
    let progress_state = std::sync::Arc::new(std::sync::Mutex::new((
        std::time::Instant::now(),
        0.0f64,
    )));
    
    let progress_state_clone = progress_state.clone();
    let progress_cb = std::sync::Arc::new(move |transferred, total| {
        let percent = if total > 0 {
            (transferred as f64 / total as f64) * 100.0
        } else {
            100.0
        };
        let now = std::time::Instant::now();
        let mut lock = progress_state_clone.lock().unwrap();
        if now.duration_since(lock.0).as_millis() >= 100 || percent - lock.1 >= 1.0 || transferred == total {
            let _ = window_clone.emit("transfer-progress", ProgressPayload { transferred, total });
            lock.0 = now;
            lock.1 = percent;
        }
    });

    let result = tokio::select! {
        res = wisp_core::receive_file(code, download_dir, relay, Some(progress_cb)) => {
            res.map_err(|e| e.to_string())
        }
        _ = token.cancelled() => {
            Err("Transfer cancelled by user".to_string())
        }
    };

    if let Err(ref e) = result {
        let _ = window.emit("transfer-error", e.clone());
    }

    result
}

#[tauri::command]
fn cancel_transfer(session_id: String, state: tauri::State<'_, TransferManager>) {
    if let Some(token) = state.sessions.lock().unwrap().get(&session_id) {
        token.cancel();
    }
}

#[derive(serde::Serialize)]
struct DeviceInfo {
    friendly_name: String,
    fingerprint: String,
}

#[tauri::command]
fn get_device_info() -> Result<DeviceInfo, String> {
    let setup = wisp_core::transport::make_persistent_server_config()
        .map_err(|e| format!("Failed to load persistent identity: {e}"))?;
    Ok(DeviceInfo {
        friendly_name: get_friendly_name(),
        fingerprint: hex::encode(setup.fingerprint),
    })
}

#[tauri::command]
async fn start_pairing_host(
    _window: tauri::Window,
    session_id: String,
    code: String,
    state: tauri::State<'_, TransferManager>,
) -> Result<wisp_core::pairing::PeerExchange, String> {
    let token = CancellationToken::new();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), token.clone());
    }
    let _guard = SessionGuard {
        sessions: &state.sessions,
        session_id: session_id.clone(),
    };

    let friendly_name = get_friendly_name();
    let setup = wisp_core::transport::make_persistent_server_config()
        .map_err(|e| format!("Failed to load persistent identity: {e}"))?;
    let fingerprint_hex = hex::encode(setup.fingerprint);

    let ip = local_ip_address::local_ip()
        .map_err(|e| format!("Could not resolve local IP: {e}"))?;
    let ipv4 = match ip {
        IpAddr::V4(v4) => v4,
        _ => return Err("Only IPv4 loopbacks supported".to_string()),
    };

    let server_addr = SocketAddr::new(IpAddr::V4(ipv4), 0);
    let server_ep = quinn::Endpoint::server(setup.config, server_addr)
        .map_err(|e| format!("Could not bind QUIC server: {e}"))?;
    let port = server_ep.local_addr().unwrap().port();

    let _advert = wisp_core::discovery::advertise(&code, ipv4, port, &fingerprint_hex)
        .map_err(|e| format!("mDNS advertisement failed: {e}"))?;

    let incoming = server_ep.accept().await
        .ok_or_else(|| "QUIC pairing listener shut down".to_string())?;
    let connection = incoming.await
        .map_err(|e| format!("QUIC pairing connection failed: {e}"))?;

    let (mut send, mut recv) = connection.accept_bi().await
        .map_err(|e| format!("Failed to open bidirectional stream: {e}"))?;

    let mut tls_unique = [0u8; 32];
    connection.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[])
        .map_err(|e| format!("Failed to export channel binding: {:?}", e))?;

    let peer_info = tokio::select! {
        res = wisp_core::pairing::run_pairing_host(&code, &friendly_name, &fingerprint_hex, &mut send, &mut recv, &tls_unique) => {
            res.map_err(|e| e.to_string())
        }
        _ = token.cancelled() => {
            Err("Pairing cancelled by user".to_string())
        }
    }?;

    if let Ok(mut config) = wisp_core::config::Config::load() {
        let clean_fingerprint = peer_info.certificate_fingerprint.clone();
        config.trusted_peers.insert(
            clean_fingerprint.clone(),
            wisp_core::config::TrustedPeer {
                friendly_name: peer_info.friendly_name.clone(),
                certificate_fingerprint: clean_fingerprint,
                last_seen_ip: Some(connection.remote_address().ip().to_string()),
            },
        );
        let _ = config.save();
    }

    Ok(peer_info)
}

#[tauri::command]
async fn pair_with_peer(
    code: String,
    address: String,
    fingerprint: String,
) -> Result<wisp_core::pairing::PeerExchange, String> {
    let friendly_name = get_friendly_name();
    let fingerprint_bytes = hex::decode(&fingerprint)
        .map_err(|e| format!("Invalid fingerprint encoding: {e}"))?;
    let expected_fp: [u8; 32] = fingerprint_bytes.try_into()
        .map_err(|_| "Fingerprint must be 32 bytes".to_string())?;

    let server_addr: SocketAddr = address.parse()
        .map_err(|e| format!("Invalid socket address: {e}"))?;

    let cfg = wisp_core::transport::make_client_config(expected_fp)
        .map_err(|e| format!("Failed to build client configuration: {e}"))?;
    let mut ep = quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .map_err(|e| format!("Failed to create client endpoint: {e}"))?;
    ep.set_default_client_config(cfg);

    let connection = ep.connect(server_addr, "wisp")
        .map_err(|e| format!("QUIC connection builder failed: {e}"))?
        .await
        .map_err(|e| format!("QUIC pairing connection failed: {e}"))?;

    let (mut send, mut recv) = connection.open_bi().await
        .map_err(|e| format!("Failed to open bidirectional stream: {e}"))?;

    let mut tls_unique = [0u8; 32];
    connection.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[])
        .map_err(|e| format!("Failed to export channel binding: {:?}", e))?;

    let peer_info = wisp_core::pairing::run_pairing_client(&code, &friendly_name, &fingerprint, &mut send, &mut recv, &tls_unique)
        .await
        .map_err(|e| e.to_string())?;

    if let Ok(mut config) = wisp_core::config::Config::load() {
        let clean_fingerprint = peer_info.certificate_fingerprint.clone();
        config.trusted_peers.insert(
            clean_fingerprint.clone(),
            wisp_core::config::TrustedPeer {
                friendly_name: peer_info.friendly_name.clone(),
                certificate_fingerprint: clean_fingerprint,
                last_seen_ip: Some(server_addr.ip().to_string()),
            },
        );
        let _ = config.save();
    }

    Ok(peer_info)
}

#[tauri::command]
fn get_trusted_peers() -> Result<Vec<wisp_core::config::TrustedPeer>, String> {
    let config = wisp_core::config::Config::load()
        .map_err(|e| e.to_string())?;
    Ok(config.trusted_peers.into_values().collect())
}

#[tauri::command]
fn delete_trusted_peer(fingerprint: String) -> Result<(), String> {
    let mut config = wisp_core::config::Config::load()
        .map_err(|e| e.to_string())?;
    config.trusted_peers.remove(&fingerprint);
    config.save().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .manage(TransferManager::default())
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      
      // Spawn LAN peer active discovery and incoming direct transfer detector
      let app_handle = app.handle().clone();
      tauri::async_runtime::spawn(async move {
          let setup = match wisp_core::transport::make_persistent_server_config() {
              Ok(s) => s,
              Err(_) => return,
          };
          let my_fp_hex = hex::encode(setup.fingerprint);
          let target_ch = wisp_core::code_commitment(&my_fp_hex);

          loop {
              // 1. Browse online LAN devices
              if let Ok(peers) = wisp_core::discovery::browse_peers(Duration::from_millis(600)) {
                  let _ = app_handle.emit("peers-updated", peers);
              }

              // 2. Scan for incoming files targeted directly to us
              if let Ok(daemon) = mdns_sd::ServiceDaemon::new() {
                  if let Ok(receiver) = daemon.browse(wisp_core::discovery::SERVICE_TYPE) {
                      if let Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) = receiver.recv_timeout(Duration::from_millis(600)) {
                          if info.get_property_val_str("ch") == Some(target_ch.as_str()) {
                              if let Some(sender_fp) = info.get_property_val_str("fp") {
                                  if let Ok(config) = wisp_core::config::Config::load() {
                                      if let Some(peer) = config.trusted_peers.get(&sender_fp.to_string()) {
                                          let addr = info.get_addresses().iter().find_map(|a| match a {
                                              std::net::IpAddr::V4(v4) => Some(v4),
                                              _ => None,
                                          });
                                          if let Some(ip) = addr {
                                              let port = info.get_port();
                                              #[derive(Clone, serde::Serialize)]
                                              struct IncomingNotification {
                                                  friendly_name: String,
                                                  fingerprint: String,
                                                  address: String,
                                              }
                                              let _ = app_handle.emit("incoming-paired-file", IncomingNotification {
                                                  friendly_name: peer.friendly_name.clone(),
                                                  fingerprint: sender_fp.to_string(),
                                                  address: format!("{}:{}", ip, port),
                                              });
                                          }
                                      }
                                  }
                              }
                          }
                      }
                  }
                  let _ = daemon.shutdown();
              }

              tokio::time::sleep(Duration::from_secs(3)).await;
          }
      });

      // Cleanup stale .wisp-part files on startup from the default Downloads folder
      if let Some(download_dir) = dirs::download_dir() {
          if let Ok(entries) = std::fs::read_dir(download_dir) {
              for entry in entries.filter_map(|e| e.ok()) {
                  let path = entry.path();
                  if path.is_file() && path.extension().map_or(false, |ext| ext == "wisp-part") {
                      let _ = std::fs::remove_file(path);
                  }
              }
          }
      }
      
      Ok(())
    })
    .invoke_handler(tauri::generate_handler![
        generate_pairing_code,
        open_file_dialog,
        open_dir_dialog,
        start_send_session,
        start_recv_session,
        cancel_transfer,
        get_device_info,
        start_pairing_host,
        pair_with_peer,
        get_trusted_peers,
        delete_trusted_peer
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
