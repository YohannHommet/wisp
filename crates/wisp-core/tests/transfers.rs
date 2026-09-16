//! Public API tests: actual sockets, generated codes, and the full session lifecycle.
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;
use wisp_core::{
    receive_file, send_file, Event, EventHandler, PairingCode, ReceiveOptions, SendOptions,
};

fn quiet() -> EventHandler {
    Arc::new(|_| {})
}
async fn start(
    path: &Path,
    callback: EventHandler,
) -> (
    tokio::task::JoinHandle<anyhow::Result<wisp_core::TransferReceipt>>,
    PairingCode,
    SocketAddr,
) {
    let (tx, rx) = oneshot::channel();
    let tx = Mutex::new(Some(tx));
    let handler: EventHandler = Arc::new(move |event| {
        if let Event::Ready {
            ref code, address, ..
        } = event
        {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send((code.parse::<PairingCode>().unwrap(), address));
            }
        }
        callback(event);
    });
    let mut options = SendOptions::new(path.to_owned());
    options.bind = Some(Ipv4Addr::LOCALHOST);
    options.discovery = false;
    options.timeouts.pake = 2;
    options.timeouts.block_transfer = 2;
    options.timeouts.wait = 5;
    let task = tokio::spawn(send_file(options, handler));
    let (code, address) = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .unwrap()
        .unwrap();
    (task, code, address)
}
fn receiver(code: PairingCode, address: SocketAddr, dir: &Path) -> ReceiveOptions {
    let mut opts = ReceiveOptions::new(code, dir.to_owned());
    opts.address = Some(address);
    opts.timeouts.pake = 2;
    opts.timeouts.block_transfer = 2;
    opts
}

#[tokio::test]
async fn complete_sessions_empty_small_and_multimegabyte() {
    for content in [
        vec![],
        b"hello wisp".to_vec(),
        (0u32..524_288).flat_map(u32::to_le_bytes).collect(),
    ] {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let path = source.path().join("file.bin");
        std::fs::write(&path, &content).unwrap();
        let (sender, code, address) = start(&path, quiet()).await;
        let receipt = receive_file(receiver(code, address, destination.path()), quiet())
            .await
            .unwrap();
        let sent = sender.await.unwrap().unwrap();
        assert_eq!(sent.hash, receipt.hash);
        assert_eq!(sent.size, content.len() as u64);
        assert_eq!(std::fs::read(receipt.saved_to.unwrap()).unwrap(), content);
        assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 1);
    }
}

#[tokio::test]
async fn wrong_secret_with_correct_locator_fails_both_sides_and_writes_nothing() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let path = source.path().join("secret");
    std::fs::write(&path, b"secret").unwrap();
    let (sender, code, address) = start(&path, quiet()).await;
    let mut words: Vec<_> = code.expose().split('-').collect();
    words[4] = if words[4] == "amber" {
        "tiger"
    } else {
        "amber"
    };
    let wrong = words.join("-").parse().unwrap();
    assert!(
        receive_file(receiver(wrong, address, destination.path()), quiet())
            .await
            .is_err()
    );
    assert!(sender.await.unwrap().is_err());
    assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn receiver_limit_rejects_without_publishing_and_sender_cannot_claim_delivery() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let path = source.path().join("data");
    std::fs::write(&path, b"too large").unwrap();
    let (sender, code, address) = start(&path, quiet()).await;
    let mut options = receiver(code, address, destination.path());
    options.max_size = 1;
    let err = receive_file(options, quiet()).await.unwrap_err();
    assert!(format!("{err:#}").contains("receive limit"));
    assert!(sender.await.unwrap().is_err());
    assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn changed_source_is_not_delivered() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let path = source.path().join("data");
    std::fs::write(&path, b"original").unwrap();
    let mutate = path.clone();
    let handler: EventHandler = Arc::new(move |event| {
        if matches!(event, Event::Ready { .. }) {
            std::fs::write(&mutate, b"modified").unwrap();
        }
    });
    let (sender, code, address) = start(&path, handler).await;
    assert!(
        receive_file(receiver(code, address, destination.path()), quiet())
            .await
            .is_err()
    );
    assert!(sender.await.unwrap().is_err());
    assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn collision_preserves_existing_file_and_receipts_agree_on_saved_name() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let path = source.path().join(format!("{}.txt", "a".repeat(176)));
    std::fs::write(&path, b"new").unwrap();
    std::fs::write(destination.path().join(path.file_name().unwrap()), b"old").unwrap();
    let (sender, code, address) = start(&path, quiet()).await;
    let receipt = receive_file(receiver(code, address, destination.path()), quiet())
        .await
        .unwrap();
    let sent = sender.await.unwrap().unwrap();
    assert_eq!(sent.name, receipt.name);
    assert!(sent.name.ends_with(" (1).txt"));
    assert_eq!(
        std::fs::read(destination.path().join(path.file_name().unwrap())).unwrap(),
        b"old"
    );
}

#[tokio::test]
async fn waiting_session_expires() {
    let source = tempfile::tempdir().unwrap();
    let path = source.path().join("data");
    std::fs::write(&path, b"data").unwrap();
    let mut options = SendOptions::new(path);
    options.bind = Some(Ipv4Addr::LOCALHOST);
    options.discovery = false;
    options.timeouts.wait = 1;
    let err = tokio::time::timeout(Duration::from_secs(3), send_file(options, quiet()))
        .await
        .unwrap()
        .unwrap_err();
    assert!(format!("{err:#}").contains("code expired"));
}

#[tokio::test]
async fn receiver_save_failure_is_not_reported_as_delivery() {
    let source = tempfile::tempdir().unwrap();
    let path = source.path().join("data");
    std::fs::write(&path, b"data").unwrap();
    let (sender, code, address) = start(&path, quiet()).await;
    assert!(
        receive_file(receiver(code, address, &path.join("impossible")), quiet())
            .await
            .is_err()
    );
    assert!(sender.await.unwrap().is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"data");
}

#[tokio::test]
async fn discovery_timeout_and_cancellation_are_bounded() {
    let code = PairingCode::generate();
    assert!(
        wisp_core::discovery::find(&code, Duration::from_millis(100))
            .await
            .is_err()
    );
    let task =
        tokio::spawn(
            async move { wisp_core::discovery::find(&code, Duration::from_secs(3600)).await },
        );
    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    assert!(tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap_err()
        .is_cancelled());
}
