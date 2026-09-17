use super::*;
use tokio::sync::oneshot;

fn silent() -> EventHandler {
    Arc::new(|_| {})
}
fn limits() -> Timeouts {
    Timeouts {
        pake: 1,
        block_transfer: 1,
        discovery: 1,
        wait: 2,
    }
}
async fn connections() -> (quinn::Connection, quinn::Connection) {
    let setup = transport::make_server_config().unwrap();
    let server = Endpoint::server(setup.config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client
        .set_default_client_config(transport::make_client_config(Some(setup.fingerprint)).unwrap());
    let (a, b) = tokio::join!(
        async { server.accept().await.unwrap().await.unwrap() },
        async {
            client
                .connect(server.local_addr().unwrap(), "wisp")
                .unwrap()
                .await
                .unwrap()
        }
    );
    (a, b)
}
async fn raw_sender(conn: &quinn::Connection, code: &PairingCode) -> (SendStream, RecvStream) {
    let (mut s, mut r) = conn.accept_bi().await.unwrap();
    pake::sender_handshake(
        code.expose(),
        &mut s,
        &mut r,
        &channel_binding(conn).unwrap(),
    )
    .await
    .unwrap();
    let mut get = [0; 3];
    r.read_exact(&mut get).await.unwrap();
    assert_eq!(&get, b"GET");
    (s, r)
}

#[tokio::test]
async fn rejects_malformed_metadata_corruption_truncation_and_trailing_data() {
    for mode in [
        "zero_frame",
        "huge_frame",
        "invalid_json",
        "bad_hash",
        "truncated",
        "extra",
        "size_limit",
        "unknown_field",
        "bad_hash_format",
    ] {
        let destination = tempfile::tempdir().unwrap();
        let (sc, cc) = connections().await;
        let code = PairingCode::generate();
        let options = ReceiveOptions {
            timeouts: limits(),
            max_size: 1024,
            ..ReceiveOptions::new(code.clone(), destination.path().into())
        };
        let server = tokio::spawn(async move {
            let (mut s, _r) = raw_sender(&sc, &code).await;
            let mut meta = serde_json::json!({"name":"file.txt", "size":3, "hash":blake3::hash(b"abc").to_hex().to_string()});
            match mode {
                "zero_frame" => {
                    s.write_all(&0u32.to_be_bytes()).await.unwrap();
                }
                "huge_frame" => {
                    s.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
                        .await
                        .unwrap();
                }
                "invalid_json" => {
                    s.write_all(&1u32.to_be_bytes()).await.unwrap();
                    s.write_all(b"{").await.unwrap();
                }
                _ => {
                    if mode == "bad_hash" {
                        meta["hash"] = "0".repeat(64).into();
                    }
                    if mode == "bad_hash_format" {
                        meta["hash"] = "not-a-hash".into();
                    }
                    if mode == "size_limit" {
                        meta["size"] = 1025.into();
                    }
                    if mode == "unknown_field" {
                        meta["command"] = "execute".into();
                    }
                    write_frame(&mut s, &meta, Duration::from_secs(1))
                        .await
                        .unwrap();
                    let data: &[u8] = match mode {
                        "truncated" => b"ab",
                        "extra" => b"abcd",
                        _ => b"abc",
                    };
                    s.write_all(data).await.unwrap();
                }
            }
            s.finish().unwrap();
            let _ = s.stopped().await;
        });
        let (mut s, mut r) = cc.open_bi().await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            receiver_protocol(
                &options,
                &mut s,
                &mut r,
                &channel_binding(&cc).unwrap(),
                &silent(),
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err(), "accepted {mode}");
        cc.close(0u32.into(), b"test complete");
        server.await.unwrap();
        assert_eq!(
            std::fs::read_dir(destination.path()).unwrap().count(),
            0,
            "left a file after {mode}"
        );
    }
}

#[tokio::test]
async fn channel_binding_mismatch_fails_before_metadata() {
    let (sc, cc) = connections().await;
    let code = PairingCode::generate();
    let other = code.clone();
    let server = tokio::spawn(async move {
        let (mut s, mut r) = sc.accept_bi().await.unwrap();
        let mut binding = channel_binding(&sc).unwrap();
        binding[0] ^= 1;
        tokio::time::timeout(
            Duration::from_secs(2),
            pake::sender_handshake(code.expose(), &mut s, &mut r, &binding),
        )
        .await
    });
    let (mut s, mut r) = cc.open_bi().await.unwrap();
    let result = pake::receiver_handshake(
        other.expose(),
        &mut s,
        &mut r,
        &channel_binding(&cc).unwrap(),
    )
    .await;
    assert!(result.is_err());
    cc.close(0u32.into(), b"test complete");
    let server_result = server.await.unwrap();
    assert!(!matches!(server_result, Ok(Ok(()))));
}

#[tokio::test]
async fn absent_or_forged_receipt_never_confirms_delivery() {
    for forge in [false, true] {
        let source = tempfile::tempdir().unwrap();
        let path = source.path().join("data");
        std::fs::write(&path, b"abc").unwrap();
        let mut prepared = PreparedFile::open(&SendOptions::new(path), &silent())
            .await
            .unwrap();
        let code = PairingCode::generate();
        let other = code.clone();
        let (sc, cc) = connections().await;
        let sender = tokio::spawn(async move {
            let (mut s, mut r) = sc.accept_bi().await.unwrap();
            sender_protocol(
                &code,
                &mut prepared,
                &mut s,
                &mut r,
                &channel_binding(&sc).unwrap(),
                &limits(),
                &silent(),
            )
            .await
        });
        let (mut s, mut r) = cc.open_bi().await.unwrap();
        pake::receiver_handshake(
            other.expose(),
            &mut s,
            &mut r,
            &channel_binding(&cc).unwrap(),
        )
        .await
        .unwrap();
        s.write_all(b"GET").await.unwrap();
        let _ = r.read_to_end(MAX_FRAME + 100).await.unwrap();
        if forge {
            write_frame(
                &mut s,
                &VerifiedReceipt {
                    name: "data".into(),
                    size: 3,
                    hash: "0".repeat(64),
                },
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        }
        s.finish().unwrap();
        assert!(sender.await.unwrap().is_err());
    }
}

#[tokio::test]
async fn cancelled_receiver_removes_its_partial_file() {
    let destination = tempfile::tempdir().unwrap();
    let (sc, cc) = connections().await;
    let code = PairingCode::generate();
    let opts = ReceiveOptions {
        timeouts: limits(),
        ..ReceiveOptions::new(code.clone(), destination.path().into())
    };
    let server = tokio::spawn(async move {
        let (mut s, _r) = raw_sender(&sc, &code).await;
        write_frame(
            &mut s,
            &FileMeta {
                name: "data".into(),
                size: 100,
                hash: "0".repeat(64),
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        s.write_all(b"incomplete").await.unwrap();
        std::future::pending::<()>().await;
    });
    let (tx, rx) = oneshot::channel();
    let tx = std::sync::Mutex::new(Some(tx));
    let event: EventHandler = Arc::new(move |event| {
        if matches!(event, Event::Progress { .. }) {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
    });
    let client = tokio::spawn(async move {
        let (mut s, mut r) = cc.open_bi().await.unwrap();
        receiver_protocol(
            &opts,
            &mut s,
            &mut r,
            &channel_binding(&cc).unwrap(),
            &event,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(3), rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 1);
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn lost_receipt_preserves_verified_local_file_and_emits_warning() {
    let destination = tempfile::tempdir().unwrap();
    let (sc, cc) = connections().await;
    let code = PairingCode::generate();
    let opts = ReceiveOptions {
        timeouts: limits(),
        ..ReceiveOptions::new(code.clone(), destination.path().into())
    };
    let server = tokio::spawn(async move {
        let (mut s, mut r) = raw_sender(&sc, &code).await;
        r.stop(0u32.into()).unwrap();
        write_frame(
            &mut s,
            &FileMeta {
                name: "data".into(),
                size: 3,
                hash: blake3::hash(b"abc").to_hex().to_string(),
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        s.write_all(b"abc").await.unwrap();
        s.finish().unwrap();
        let _ = sc.closed().await;
    });
    let warned = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = warned.clone();
    let events: EventHandler = Arc::new(move |event| {
        if matches!(event, Event::Warning { .. }) {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let (mut s, mut r) = cc.open_bi().await.unwrap();
    let receipt = receiver_protocol(
        &opts,
        &mut s,
        &mut r,
        &channel_binding(&cc).unwrap(),
        &events,
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(receipt.saved_to.unwrap()).unwrap(), b"abc");
    assert!(warned.load(std::sync::atomic::Ordering::SeqCst));
    cc.close(0u32.into(), b"done");
    server.await.unwrap();
}

#[tokio::test]
async fn sender_cannot_block_receiver_before_authentication() {
    let mut setup = transport::make_server_config().unwrap();
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_bidi_streams(0u8.into());
    setup.config.transport_config(Arc::new(config));
    let server = Endpoint::server(setup.config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        connection.close(0u32.into(), b"test complete");
    });
    let destination = tempfile::tempdir().unwrap();
    let mut options = ReceiveOptions::new(PairingCode::generate(), destination.path().into());
    options.address = Some(address);
    options.timeouts.pake = 1;
    let error = tokio::time::timeout(Duration::from_secs(2), receive_file(options, silent()))
        .await
        .expect("receiver ignored its authentication timeout")
        .unwrap_err();
    assert!(format!("{error:#}").contains("did not allow authentication"));
    peer.abort();
    let _ = peer.await;
}
