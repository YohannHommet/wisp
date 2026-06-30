use std::collections::HashMap;
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tauri::Emitter;

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
        cancel_transfer
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
