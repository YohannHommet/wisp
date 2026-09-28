# Architecture

Wisp is a two-crate workspace. `wisp-core` owns transfers, and `wisp` is the terminal adapter. There is no daemon or persistent device registry.

| Module | Responsibility |
|---|---|
| `code` | Generate, parse, normalize and redact typed pairing codes |
| `config` | Explicit config loading and timeout validation |
| `discovery` | Advertise and find public session locators with cancellation-aware mDNS polling |
| `transport` | Ephemeral QUIC/TLS configuration and optional discovery fingerprint pinning |
| `pake` | SPAKE2 and role-specific channel-bound confirmation |
| `storage` | Private temporary files, portable filenames and no-overwrite publication |
| `transfer` | Session lifecycle, bounded wire frames, streaming verification and receipts |
| CLI | Arguments, configuration precedence, progress, JSON events, signals and exit codes |

## Public API

`SendOptions::new(path)` and `ReceiveOptions::new(code, directory)` make configuration explicit. Core operations never read global config or print to a terminal. A synchronous event callback reports lifecycle stages and throttled progress. `send_file` generates the only code used by that session and emits it only after listening and attempting discovery registration. `receive_file` returns the verified local path. Both return a `TransferReceipt`.

Callbacks must be fast. `Ready` contains the code, so event streams must not be sent to external telemetry. Code types redact passwords in Debug output. Transfer options validate timeouts even when called directly without the CLI.

Dropping a transfer future closes its endpoint and withdraws discovery. The CLI handles signals with `tokio::select!` and returns an exit status only after the transfer future has dropped. It does not call `process::exit` in the transfer path. Discovery does not use uncancellable `spawn_blocking` waits: bounded batches of mDNS events are polled asynchronously.

Source reads and hashing use Tokio file I/O on the same open handle. Destination writes are buffered synchronous writes, bounded by received chunks, so temporary-file ownership and cleanup are deterministic across cancellation. Flush, file sync and publication are synchronous; slow local filesystems can delay cancellation during those operations. No detached task is allowed to publish a file after the transfer future has been cancelled.

## WSP wire sequence

1. QUIC handshake with ALPN `wsp/2`.
2. Receiver presents 32-byte `locator_token` proof of intent bound to the TLS exporter. If valid, peers execute SPAKE2 mutual key confirmation with directional role-bound MACs.
3. Receiver sends `GET` to initiate the session stream.
4. Sender writes big-endian u32 length-prefixed `FileMeta`.
5. Negotiation & streaming:
   - **Single-file**: Receiver sends `TransferRequest` (`Full` or `Resume { offset }`), sender responds with `TransferResponse` (`Accepted` or `Rejected`), and sender streams chunks from `start_offset`.
   - **Directory**: Sender streams typed `DirFrame` frames (`Dir`, `FileHeader`, chunk payload, `FileEnd`, `EndDir`) with domain-separated BLAKE3 tree hashing (`WISP_DIR_V1`).
6. Receiver validates metadata, size, FIN and BLAKE3 checksums, then syncs and atomically publishes without overwriting.
7. Receiver writes a length-prefixed `VerifiedReceipt`, then FIN.
8. Sender validates receipt and FIN. Receiver waits for transport acknowledgement; connections close cleanly.

Every network stage is bounded. The 3-attempt budget policy with 1.0s delay balances human typo recovery with strict online guess resistance ($P \approx 1.45 \times 10^{-8}$). Spurious network probes without valid session intent are rejected as `InvalidIntent` without consuming guess attempts.

If a file is saved but acknowledgement is lost, local success and remote uncertainty are both represented honestly. A distributed protocol cannot eliminate every ambiguity caused by disconnection.

## Architecture Decision Records (ADRs)

Detailed architectural choices, protocol specifications, and storage durability guarantees are documented in [`docs/adr/`](adr/README.md):
- [ADR-0001: In-Flight Directory Streaming Architecture](adr/0001-in-flight-directory-streaming.md)
- [ADR-0002: Transfer Resumption and Periodic Checkpointing](adr/0002-transfer-resumption-and-checkpointing.md)
- [ADR-0003: LAN PAKE DoS Mitigation and Bounded Authentication Budget](adr/0003-lan-pake-dos-mitigation-and-bounded-auth-budget.md)

## Scope decisions

IPv4 LAN only; transfers one file or one directory tree per invocation. `--bind` selects an interface and `--address` bypasses multicast discovery. Single-file transfers support periodic 16 MiB disk checkpointing for seamless resumption upon network reconnection. No automatic interface fanout, UDP hole punching, internet relay fallback, background daemon receiving, or persistent queues.

Tests cover the public API, raw hostile peers, actual CLI subprocesses, directory tree integrity, path collisions, and cancellation. Discovery testing is explicitly selected on a multicast-capable network. Release checks run the portable suite on Linux, macOS and Windows and native release targets before drafting artifacts.
