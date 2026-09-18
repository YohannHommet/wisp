//! Exercise the shipped executable: parsing its actual generated code, exit status
//! and JSON receipts. No mocks of the library or network.
use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

struct Process {
    child: Child,
    events: Receiver<Value>,
}
impl Process {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wisp"))
            .args(["--no-config", "--json"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, events) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                let value = serde_json::from_str(&line).expect("stdout must be NDJSON");
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        Self { child, events }
    }
    fn event(&self, expected: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let value = self
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("missing CLI event");
            assert_ne!(value["event"], "error", "{value}");
            if value["event"] == expected {
                return value;
            }
        }
    }
    fn finish(&mut self) -> (ExitStatus, Vec<Value>) {
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "CLI did not exit in 15s");
            std::thread::sleep(Duration::from_millis(20));
        };
        let events = self.events.iter().collect();
        (status, events)
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn transfer(discovery: bool) {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let file = source.path().join("hello.txt");
    std::fs::write(&file, b"Wisp CLI end-to-end\n").unwrap();
    let mut args = vec!["send", path(&file), "--wait", "10"];
    if !discovery {
        args.extend(["--no-discovery", "--bind", "127.0.0.1"]);
    }
    let mut sender = Process::start(&args);
    let ready = sender.event("ready");
    let mut args = vec![
        "recv",
        ready["code"].as_str().unwrap(),
        "--dir",
        path(destination.path()),
        "--timeout",
        "5",
    ];
    if !discovery {
        args.extend(["--address", ready["address"].as_str().unwrap()]);
    } else {
        assert_eq!(ready["discovery"], true);
    }
    let mut receiver = Process::start(&args);
    let (status, received) = receiver.finish();
    assert!(status.success(), "{received:?}");
    let (status, sent) = sender.finish();
    assert!(status.success(), "{sent:?}");
    let received = received.iter().find(|v| v["event"] == "completed").unwrap();
    let sent = sent.iter().find(|v| v["event"] == "completed").unwrap();
    assert_eq!(received["receipt"]["hash"], sent["receipt"]["hash"]);
    assert_eq!(
        std::fs::read(destination.path().join("hello.txt")).unwrap(),
        b"Wisp CLI end-to-end\n"
    );
}

#[test]
fn two_cli_processes_exchange_the_displayed_code_and_verified_receipts() {
    transfer(false);
}

#[test]
fn rejected_transfer_then_repeated_delivery_preserves_existing_files() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let name = "rapport été.bin";
    let file = source.path().join(name);
    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(&file, &payload).unwrap();
    std::fs::write(destination.path().join(name), b"original").unwrap();

    for attempt in 0..3 {
        let mut sender = Process::start(&[
            "send",
            path(&file),
            "--no-discovery",
            "--bind",
            "127.0.0.1",
            "--wait",
            "10",
        ]);
        let ready = sender.event("ready");
        let mut receiver = Process::start(&[
            "recv",
            ready["code"].as_str().unwrap(),
            "--address",
            ready["address"].as_str().unwrap(),
            "--dir",
            path(destination.path()),
            "--timeout",
            "5",
            "--max-size",
            if attempt == 0 { "1" } else { "2MiB" },
        ]);
        let (received_status, received) = receiver.finish();
        let (sent_status, sent) = sender.finish();
        if attempt == 0 {
            for (status, events) in [(received_status, &received), (sent_status, &sent)] {
                assert_eq!(status.code(), Some(1), "{events:?}");
                assert_eq!(events.last().unwrap()["event"], "error", "{events:?}");
                assert!(!events.iter().any(|event| event["event"] == "completed"));
            }
        } else {
            assert!(received_status.success(), "{received:?}");
            assert!(sent_status.success(), "{sent:?}");
            let received = &received.last().unwrap()["receipt"];
            let sent = &sent.last().unwrap()["receipt"];
            let saved = destination
                .path()
                .join(format!("rapport été ({attempt}).bin"));
            assert_eq!(received["saved_to"], path(&saved));
            assert_eq!(received["hash"], sent["hash"]);
            assert_eq!(received["name"], sent["name"]);
            assert_eq!(received["size"], payload.len());
            assert_eq!(std::fs::read(saved).unwrap(), payload);
        }
        assert_eq!(
            std::fs::read(destination.path().join(name)).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read_dir(destination.path()).unwrap().count(),
            attempt + 1
        );
    }
}

#[test]
#[ignore = "requires an IPv4 LAN interface and multicast; run explicitly with --ignored"]
fn discovery_two_cli_processes() {
    transfer(true);
}

#[test]
fn invalid_input_fails_before_network_and_json_runtime_errors_are_structured() {
    let output = Command::new(env!("CARGO_BIN_EXE_wisp"))
        .args(["--no-config", "recv", "7-tiger-saturn"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let source = tempfile::tempdir().unwrap();
    let mut process = Process::start(&["send", path(&source.path().join("missing"))]);
    let (status, events) = process.finish();
    assert_eq!(status.code(), Some(1));
    assert_eq!(events.last().unwrap()["event"], "error");
}

#[cfg(unix)]
#[test]
fn ctrl_c_returns_130_and_terminates_waiting_sender() {
    let source = tempfile::tempdir().unwrap();
    let file = source.path().join("data");
    std::fs::write(&file, b"data").unwrap();
    let mut sender =
        Process::start(&["send", path(&file), "--no-discovery", "--bind", "127.0.0.1"]);
    sender.event("ready");
    assert!(Command::new("kill")
        .args(["-INT", &sender.child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let (status, events) = sender.finish();
    assert_eq!(status.code(), Some(130));
    assert_eq!(events.last().unwrap()["exit_code"], 130);
}

#[cfg(target_os = "linux")]
#[test]
fn json_receipt_handles_non_utf8_destination_without_panicking() {
    use std::os::unix::ffi::OsStringExt;
    let source = tempfile::tempdir().unwrap();
    let file = source.path().join("data");
    std::fs::write(&file, b"data").unwrap();
    let destination = source
        .path()
        .join(std::ffi::OsString::from_vec(b"received-\xff".to_vec()));
    let mut sender =
        Process::start(&["send", path(&file), "--no-discovery", "--bind", "127.0.0.1"]);
    let ready = sender.event("ready");
    let output = Command::new(env!("CARGO_BIN_EXE_wisp"))
        .args([
            "--no-config",
            "--json",
            "recv",
            ready["code"].as_str().unwrap(),
            "--address",
            ready["address"].as_str().unwrap(),
            "--dir",
        ])
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.last().unwrap()["event"], "completed");
    assert_eq!(std::fs::read(destination.join("data")).unwrap(), b"data");
    let (status, events) = sender.finish();
    assert!(status.success(), "{events:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn failed_stdout_stops_sender_and_reports_actionable_error() {
    let source = tempfile::tempdir().unwrap();
    let file = source.path().join("data");
    std::fs::write(&file, b"data").unwrap();
    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wisp"));
        command.arg("--no-config");
        if json {
            command.arg("--json");
        }
        let child = command
            .args([
                "send",
                path(&file),
                "--no-discovery",
                "--bind",
                "127.0.0.1",
                "--wait",
                "30",
            ])
            .stdout(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .unwrap(),
            )
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (_, events) = mpsc::channel();
        let mut process = Process { child, events };
        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = process.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "sender kept waiting after stdout failed (json={json})"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stderr = String::new();
        std::io::Read::read_to_string(process.child.stderr.as_mut().unwrap(), &mut stderr).unwrap();
        assert_eq!(status.code(), Some(1), "json={json}: {stderr}");
        assert!(stderr.contains("stdout"), "json={json}: {stderr}");
        assert!(!stderr.contains("panicked"), "json={json}: {stderr}");
    }
}
