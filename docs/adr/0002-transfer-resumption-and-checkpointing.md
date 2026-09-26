# ADR-0002: Transfer Resumption and Periodic Checkpointing

**Date**: 2026-09-24
**Status**: accepted
**Deciders**: Yohann Hommet, Antigravity Protocol Architects

## Context

When transferring large files (e.g. 5–50 GB) over local Wi-Fi or Ethernet networks, unexpected network interruptions (Wi-Fi reconnection, laptop lid closing, interface routing changes, or accidental process cancellation) would cause Wisp to drop the QUIC connection.

In v0.2, any interrupted transfer automatically triggered cleanup of the temporary `.part` file, discarding gigabytes of already received and verified data. Users had to restart transfers from 0%, leading to bandwidth waste and user frustration.

## Decision

We implement robust, integrity-preserving transfer resumption for single-file transfers based on periodic 16 MiB disk checkpointing and atomic sidecar ledgers.

Key architectural specifications:
1. **Periodic Checkpoint Granularity (`CHECKPOINT_INTERVAL = 16 MiB`)**:
   During active streaming, the receiver flushes incoming bytes and commits a durable disk checkpoint every 16 MiB (`16 * 1024 * 1024` bytes).
2. **Atomic Ledger Sidecars (`.wisp-<hash>.resume`)**:
   Checkpoints are recorded into an atomic sidecar file `.wisp-<hash>.resume` via write-and-rename (`.resume.tmp` $\to$ `.resume`). The ledger stores the file hash, expected total size, and verified checkpoint offset.
3. **Resumption Negotiation Handshake**:
   After SPAKE2 mutual authentication and channel binding, the receiver inspects local disk state. If a valid `.part` file and matching `.resume` ledger exist:
   - Receiver requests `TransferRequest::Resume { offset }`.
   - Sender validates that `offset <= source.size` and `offset % 16MiB == 0`, and responds with `TransferResponse::Accepted` or `TransferResponse::Rejected`.
   - If accepted, the sender seeks to `offset` and begins streaming from that position.
4. **End-to-End Cryptographic Verification**:
   Even when resumed, publication to the destination file name is gated by a complete full-pass BLAKE3 hash computation from disk across the entire combined payload ($0 \dots \text{total\_size}$). Any bit-rot, corruption, or offset tampering causes immediate verification failure and purges the partial file.
5. **Cross-Platform Publication Fallback**:
   On Unix filesystems supporting hard links, publication uses `std::fs::hard_link` to eliminate TOCTOU overwrite races. For filesystems without hard link support (FAT32, exFAT on USB drives, or CIFS/NFS mounts returning `Unsupported`, `EPERM`, or `ENOTSUP`), the engine falls back to `std::fs::rename` with pre-checked non-existence.
6. **Staging Garbage Collection (`wisp clean`)**:
   A dedicated `wisp clean` command allows users to prune abandoned `.wisp-*.part` files and `.wisp-dir-*.part` staging folders older than `--older-than` (default: 24h).

## Alternatives Considered

### Alternative 1: Bao / fine-grained BLAKE3 verified tree chunk storage
- **Pros**: Every single 64 KiB chunk is cryptographically verifiable independently on receipt.
- **Cons**: Requires generating and persisting out-of-order Bao tree slices on disk; increases protocol complexity and storage overhead.
- **Why not**: 16 MiB linear checkpoints combined with full-pass BLAKE3 end-of-transfer disk verification provide complete cryptographic security with near-zero runtime overhead.

### Alternative 2: Naive byte-range HTTP-like offset resume
- **Pros**: Simplest to implement.
- **Cons**: Unsafe; a modified source file on the sender or corrupted partial buffer on the receiver would be silently combined, producing a corrupt destination file.
- **Why not**: Without strict ledger binding and end-of-transfer hashing, data integrity cannot be guaranteed.

## Consequences

### Positive
- **Fault-Tolerant Transfers**: Interrupted transfers automatically pick up where they left off without user intervention.
- **Cryptographic Soundness**: Tampered partial chunks or mismatched source files are detected and rejected.
- **Safe Opt-Out**: Users can bypass resumption using `wisp recv --no-resume` if a fresh download from byte 0 is explicitly desired.
- **Portable Across Media**: Works seamlessly across POSIX filesystems, NTFS, exFAT, and external USB flash drives.

### Negative
- Partial transfers leave `.wisp-<hash>.part` and `.wisp-<hash>.resume` on disk until completed or cleaned.
- Directory resumption is not yet supported in this initial release (directories restart from 0 if cancelled).

### Risks
- Local multi-user disk tampering: mitigated by strict file mode permissions (`0o600` on Unix), `O_NOFOLLOW` flag to prevent symlink attacks, and full BLAKE3 verification pass before publishing.
