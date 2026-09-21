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
    options.timeouts.block_transfer = 10;
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
    opts.timeouts.block_transfer = 10;
    opts
}

#[tokio::test]
async fn complete_sessions_empty_small_and_multimegabyte() {
    for content in [
        vec![],
        b"hello wisp".to_vec(),
        (0u32..524_288).flat_map(u32::to_le_bytes).collect(),
        vec![0u8; 64 * 1024 * 1024],
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

#[tokio::test]
async fn complete_directory_transfer_with_nested_structure() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let project = source.path().join("my_project");
    std::fs::create_dir_all(project.join("src/utils")).unwrap();
    std::fs::create_dir_all(project.join("empty_dir")).unwrap();

    std::fs::write(project.join("README.md"), b"# Hello Directory").unwrap();
    std::fs::write(project.join("src/main.rs"), b"fn main() {}").unwrap();
    std::fs::write(project.join("src/utils/helpers.rs"), b"pub fn helper() {}").unwrap();

    let (sender, code, address) = start(&project, quiet()).await;
    let receipt = receive_file(receiver(code, address, destination.path()), quiet())
        .await
        .unwrap();
    let sent = sender.await.unwrap().unwrap();

    assert!(sent.is_directory);
    assert!(receipt.is_directory);
    assert_eq!(sent.name, "my_project");
    assert_eq!(receipt.name, "my_project");
    assert_eq!(sent.hash, receipt.hash);
    let expected_size =
        (b"# Hello Directory".len() + b"fn main() {}".len() + b"pub fn helper() {}".len()) as u64;
    assert_eq!(sent.size, expected_size);
    assert_eq!(receipt.size, expected_size);

    let dest_project = destination.path().join("my_project");
    assert!(dest_project.is_dir());
    assert_eq!(
        std::fs::read(dest_project.join("README.md")).unwrap(),
        b"# Hello Directory"
    );
    assert_eq!(
        std::fs::read(dest_project.join("src/main.rs")).unwrap(),
        b"fn main() {}"
    );
    assert_eq!(
        std::fs::read(dest_project.join("src/utils/helpers.rs")).unwrap(),
        b"pub fn helper() {}"
    );
    assert!(dest_project.join("empty_dir").is_dir());
    assert_eq!(
        std::fs::read_dir(dest_project.join("empty_dir")).unwrap().count(),
        0
    );
}

#[tokio::test]
async fn empty_directory_transfer() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let empty_dir = source.path().join("empty_dir");
    std::fs::create_dir(&empty_dir).unwrap();

    let (sender, code, address) = start(&empty_dir, quiet()).await;
    let receipt = receive_file(receiver(code, address, destination.path()), quiet())
        .await
        .unwrap();
    let sent = sender.await.unwrap().unwrap();

    assert!(sent.is_directory);
    assert!(receipt.is_directory);
    assert_eq!(sent.name, "empty_dir");
    assert_eq!(receipt.name, "empty_dir");
    assert_eq!(sent.size, 0);
    assert_eq!(receipt.size, 0);
    assert_eq!(sent.hash, receipt.hash);

    let dest_dir = destination.path().join("empty_dir");
    assert!(dest_dir.is_dir());
    assert_eq!(std::fs::read_dir(dest_dir).unwrap().count(), 0);
}

#[tokio::test]
async fn directory_collision_preserves_existing_directory() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();

    let existing_dir = destination.path().join("backup");
    std::fs::create_dir(&existing_dir).unwrap();
    std::fs::write(existing_dir.join("old.txt"), b"old file").unwrap();

    let source_dir = source.path().join("backup");
    std::fs::create_dir(&source_dir).unwrap();
    std::fs::write(source_dir.join("new.txt"), b"new file").unwrap();

    let (sender, code, address) = start(&source_dir, quiet()).await;
    let receipt = receive_file(receiver(code, address, destination.path()), quiet())
        .await
        .unwrap();
    let sent = sender.await.unwrap().unwrap();

    assert_eq!(sent.name, "backup (1)");
    assert_eq!(receipt.name, "backup (1)");

    assert_eq!(
        std::fs::read(existing_dir.join("old.txt")).unwrap(),
        b"old file"
    );
    assert!(!existing_dir.join("new.txt").exists());

    let collided_dir = destination.path().join("backup (1)");
    assert!(collided_dir.is_dir());
    assert_eq!(
        std::fs::read(collided_dir.join("new.txt")).unwrap(),
        b"new file"
    );
}

