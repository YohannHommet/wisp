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

## WSP/2 wire sequence

1. QUIC handshake with ALPN `wsp/2`.
2. SPAKE2 and mutual key confirmation bound to the TLS exporter.
3. Receiver sends exactly `GET`, leaving its send stream open for the receipt.
4. Sender writes a big-endian u32 frame length, JSON `{name,size,hash}`, exactly the prepared bytes, then stream FIN.
5. Receiver validates metadata, size, FIN and checksum, then syncs and publishes without overwriting.
6. Receiver writes a length-prefixed JSON `{name,size,hash}` receipt, using the actual collision-resolved name, then FIN.
7. Sender validates the receipt and its FIN. Receiver waits for transport acknowledgement of its receipt; connections then close.

Every network stage is bounded. The one-attempt policy is deliberate: automatic retries with the same short password would enlarge the online guessing budget. Retry at the user level creates a new session and code.

If a file is saved but acknowledgement is lost, local success and remote uncertainty are both represented honestly. A distributed protocol cannot eliminate every ambiguity caused by disconnection.

## Scope decisions

IPv4 LAN only; one regular file per invocation. `--bind` selects an interface and `--address` bypasses multicast discovery. No automatic interface fanout, UDP hole punching, internet fallback, persistence, queues, folder traversal, resumability or background receiving. A future interface must consume this same session API and demonstrate real interoperability before joining the supported workspace.

Tests cover the public API, raw hostile peers, actual CLI subprocesses, path collisions and cancellation. Discovery testing is explicitly selected on a multicast-capable network. Release checks run the portable suite on Linux, macOS and Windows and native release targets before drafting artifacts.
