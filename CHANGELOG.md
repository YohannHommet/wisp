# Changelog

## 0.3.0 — unreleased

### Major Features
- **In-flight Directory Streaming**: Stream entire directory trees on-the-fly (`wisp send <dir>` / `wisp recv <code>`) without intermediate `.tar`/`.zip` archives. Uses domain-separated BLAKE3 tree hashing (`WISP_DIR_V1`), preserves Unix executable bits, rejects Zip Slip / traversal, and enforces monotonic lexical order.
- **Transfer Resumption & Checkpointing**: Large file transfers automatically resume from verified 16 MiB checkpoints after network disconnects or process restarts, using atomic `.resume` ledger sidecars. Resumption can be explicitly bypassed using `wisp recv --no-resume`.
- **Partial Staging Garbage Collection**: Added `wisp clean` command to prune abandoned `.wisp-*.part` staging files and directories older than `--older-than` (default 24h).
- **Architecture Hardening**: Expanded protocol message framing cap from 4 KiB to 64 KiB, added zero-allocation stack buffers for frame headers, enforced 2048-byte path limits, added non-hardlink filesystem fallback on FAT32/exFAT, and ensured publication atomicity.

## 0.2.0

Wisp returns to its original scope: a CLI for sending a regular file between two computers on the same local IPv4 network.

### Breaking changes

- Removed the unfinished Tauri/Svelte interface, WAN relay, persistent device identity and pairing registry.
- Introduced WSP/2, separate mDNS service records and codes consisting of a public eight-digit locator plus four secret words. Both computers must upgrade.
- Removed relay configuration/environment defaults. Invalid or legacy configuration now fails with migration guidance instead of being silently ignored.
- Replaced the old positional core API with explicit options, structured events and verified receipts.

### Reliability and security

- Discovery no longer publishes a hash of any secret code words.
- Codes expire and permit one incoming attempt; authentication and I/O stages are bounded.
- QUIC Retry validates a receiver's source address before the sender commits its one allowed attempt.
- Receiver stream creation is deadline-bound, and human diagnostics escape peer-controlled terminal sequences.
- Sender success requires a matching verified-save receipt.
- Source hashing and transmission use the same open file; mutation during transmission is rejected.
- Receiving uses private randomized temporary files, exact byte count/EOF/hash verification, syncing, and no-overwrite publication with collision suffixes.
- Portable filename handling covers traversal, terminal controls, Windows device names and UTF-8 length limits.
- Handled cancellation drops transfer resources and partial files; no startup sweep deletes arbitrary partial files.
- Added direct-address fallback, interface/port selection, receive size limits, NDJSON events and useful error guidance.
- Output failures terminate cleanly; valid non-UTF-8 destination paths no longer crash JSON completion.
- Large transfers use enlarged UDP socket buffers to avoid kernel packet drops and QUIC stream-gap aborts on busy LAN paths.
- Updated Quinn to 0.11.12, including upstream stream defragmentation fixes for reordered packets.
- Updated rustls to 0.23.45 to resolve RUSTSEC-2026-0285.
- Updated locked dependencies to resolve the QUIC memory-exhaustion advisory and all reported dependency warnings.

### Maintenance

- Added real CLI-process, public-API and hostile-peer regression tests, with explicit multicast testing.
- Added cross-platform CI, minimum-Rust validation, dependency auditing and a gated CLI-only draft release workflow.
- Pinned CI actions and audit tooling to reviewed immutable versions and disabled persisted checkout credentials.
- Installers verify SHA-256 checksums before replacing user-level binaries.
- Rewrote usage, architecture, threat-model and release documentation around implemented behavior.
