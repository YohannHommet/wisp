# ADR-0001: In-Flight Directory Streaming Architecture

**Date**: 2026-09-22
**Status**: accepted
**Deciders**: Yohann Hommet, Antigravity Protocol Architects

## Context

Prior to v0.3.0, Wisp only supported transferring a single regular file per session. If users needed to send a folder or multi-file project, they had to manually bundle it into a `.tar` or `.zip` archive before transmission, and extract it manually on the receiving end.

Creating intermediate archive files on disk has severe drawbacks:
1. **Disk Space Double-Jeopardy**: Archiving a 50 GB directory requires 50 GB of free staging disk space on both sender and receiver ($2\times$ disk overhead).
2. **Start-up Latency**: The sender must wait for the entire archive to be written before discovery and network streaming can begin.
3. **Security Risks (Zip Slip)**: Uncontrolled archive extraction exposes systems to directory traversal (`../`), symlink sandbox escapes, and Windows reserved device collisions (`CON`, `PRN`, `AUX`, `NUL`).

## Decision

We stream directories in-flight directly over the QUIC bidirectional stream using a native message framing protocol (`DirFrame`), without writing intermediate archive files to disk.

Key architectural specifications:
1. **Deterministic Monotonic Path Ordering**: The sender scans and emits directory entries in strict lexical sort order (`a < b`). The receiver enforces monotonicity, rejecting non-canonical sequences, out-of-order writes, or duplicate path injections.
2. **Cryptographic Tree Hashing (`WISP_DIR_V1`)**: Directory tree integrity is verified using domain-separated BLAKE3 hashing. Each directory entry feeds a prefix domain byte (`b"D\0"` for subdirectories, `b"F\0"` for files) followed by path bytes, file length, executable bit, and individual BLAKE3 file content hash. The computed root tree hash must match the sender's `DirFrame::EndDir` root hash.
3. **Security & Sandbox Isolation**: Every path segment is strictly validated by `sanitize_relative_path` (rejecting absolute paths, parent directory references `..`, backslashes `\`, control/bidi characters, and Windows reserved device stems). Symlinks are excluded from recursive scanning to prevent symlink traversal attacks.
4. **Publication Atomicity**: The receiver unpacks the streaming directory into an isolated private staging folder (`.wisp-dir-<uuid>.part`). Once fully received and tree-hash verified, it is atomically moved to the destination folder using a no-overwrite reservation loop.

## Alternatives Considered

### Alternative 1: Intermediate `.tar` / `.zip` archive on disk
- **Pros**: Uses existing single-file transfer pipeline without protocol modifications.
- **Cons**: Requires double disk space; adds latency; poor user experience.
- **Why not**: Violates Wisp's principle of lightweight, zero-overhead peer-to-peer data transfer.

### Alternative 2: Standard `tar` streaming (PAX format) over QUIC
- **Pros**: Standardized format; libraries like `tokio-tar` exist.
- **Cons**: Tar headers are difficult to validate incrementally against malicious zip-slip offsets; streaming Tar does not mandate deterministic lexical ordering or unified cryptographic tree hashing; requires parsing non-Rust or heavy format specifications.
- **Why not**: Native `DirFrame` frames are typed, serde-validated, bounded by `MAX_FRAME`, and tightly bound to BLAKE3 verification.

## Consequences

### Positive
- **Instantaneous Transfer Start**: Files begin streaming over QUIC immediately without pre-archiving.
- **Zero Temporary Disk Overhead**: Disk space consumption is limited strictly to the actual incoming files.
- **Fine-Grained Progress Reporting**: Real-time progress updates report current file name, transferred bytes, and total directory entry count.
- **Strong Integrity & Sandbox Security**: Domain-separated BLAKE3 tree hashing guarantees that no file was added, omitted, modified, or reordered in transit.

### Negative
- Directory transfers are not backward-compatible with v0.2 receivers (which only accept single-file streams).

### Risks
- Deeply nested directories could exceed protocol framing limits: mitigated by expanding `MAX_FRAME` to 64 KiB, bounding path depth to 32 segments, and capping total path length to 2048 bytes.
