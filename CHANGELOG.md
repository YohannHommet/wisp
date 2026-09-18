# Changelog

## 0.2.0 — unreleased

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
