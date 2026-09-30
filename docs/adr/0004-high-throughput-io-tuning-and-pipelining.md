# ADR-0004: High-Throughput I/O Tuning and Double-Buffered Pipelining

**Date**: 2026-09-28  
**Status**: Accepted  
**Deciders**: Yohann Hommet, Systems & Architecture Team  

## Context

In Wisp v0.2 and early v0.3, file streaming and hashing utilized conservative sequential buffer configurations:
- `CHUNK = 64 KiB` for QUIC stream writes.
- `HASH_CHUNK = 256 KiB` for BLAKE3 pre-transfer source hashing.
- Sequential lockstep read-send execution loop: `file.read(&mut buf)` followed by `quic.write_all(&buf)`.

On modern high-speed local networks (1 Gbps to 10 Gbps LANs, Wi-Fi 6/7) and NVMe solid-state storage, this sequential model introduced observable performance bottlenecks:
1. **I/O and Network Pipeline Bubbles**: When reading sequentially, the disk subsystem sits idle while Tokio and Quinn wait for network packet transmission and TCP/QUIC flow control window updates. Conversely, the QUIC transport pipeline drains while waiting for asynchronous filesystem reads.
2. **Async Task Dispatch Overhead**: At 64 KiB per chunk, a 10 GB transfer requires 160,000 asynchronous read and write cycles. The context switching overhead across Tokio's reactor and Quinn's packet loops throttled throughput.
3. **Hashing Preparation Stalls**: A 256 KiB buffer during `PreparedFile::open` resulted in excessive `spawn_blocking` and syscall handoffs, capping warm-cache preparation hashing at ~2.0 GB/s.

## Decision

We optimize data plane throughput while maintaining strict memory bounds ($O(1)$ RAM usage) and `#![forbid(unsafe_code)]` safety:

### 1. Double-Buffered Ping-Pong Pipelining
For transfers exceeding a single chunk, both single-file (`sender_file_protocol`) and directory streaming (`sender_dir_protocol`) employ an asynchronous double-buffered ping-pong architecture:
- Two reusable buffers of capacity `CHUNK` (512 KiB each) circulate between two bounded channels (`free_tx`/`free_rx` with capacity 2, and `data_tx`/`data_rx` with capacity 2).
- The reader and writer coroutines execute concurrently via `tokio::try_join!(reader, writer)`:
  - **`reader`**: Fetches a pre-allocated recycled buffer from `free_rx`, reads the next chunk from disk, and forwards it to `data_tx`.
  - **`writer`**: Drains chunks from `data_rx`, updates the BLAKE3 hasher and progress tracker, transmits data over the QUIC stream (`send.write_all`), and recycles the buffer back into `free_tx`.
- **Drain Invariant**: When the `reader` finishes reading the file and exits, dropping `free_rx`, the `writer` continues draining all remaining queued chunks from `data_rx` until EOF, ensuring complete transmission before final receipt exchange.
- **Fast-path for Small Files**: Payloads smaller than or equal to `CHUNK` bypass channel setup and transfer immediately in a single buffer read-and-send pass.

### 2. Tuned Buffer Constants
- **`CHUNK = 512 KiB`** (increased from 64 KiB): Reduces syscall and async task overhead by 8x while fitting within CPU L2/L3 cache hierarchies and QUIC congestion window dynamics.
- **`HASH_CHUNK = 1024 KiB`** (increased from 256 KiB): Amortizes Tokio's asynchronous file reads during initial BLAKE3 digest calculation, elevating hashing throughput to ~2.55 GB/s.

### 3. Bounded Backpressure and Cancellation Safety
- Maximum in-flight buffering is strictly bounded to $2 \times 512\text{ KiB} = 1\text{ MiB}$ of heap memory.
- If network transmission stalls or packet loss occurs, `data_tx` applies backpressure to pause disk reads.
- If the session is cancelled or disconnected, dropping the `try_join!` future aborts both coroutines simultaneously with zero resource leaks.
- Slowloris throughput protection (`MIN_THROUGHPUT_PER_WINDOW`) continues to be enforced in the writer loop across rolling time windows.

## Alternatives Considered

### Alternative 1: Zero-Copy `splice` / `sendfile`
- **Pros**: Direct kernel-space page transfer from filesystem cache to socket.
- **Cons**: Quinn runs QUIC over UDP and performs TLS 1.3 encryption in userspace via `rustls`. Linux kernel `sendfile` and `splice` cannot encrypt QUIC packet payloads into UDP datagrams without userspace round-trips. Furthermore, `splice` is non-portable across Windows and macOS.
- **Why not**: Incompatible with QUIC TLS encryption and cross-platform portability.

### Alternative 2: Unbounded Pre-Reading Channel
- **Pros**: Simple reader-writer loop using a single unbounded channel.
- **Cons**: On fast NVMe drives connected to slow or jittery Wi-Fi receivers, an unbounded reader would buffer gigabytes of data into RAM, leading to memory exhaustion (OOM).
- **Why not**: Violates Wisp's bounded memory invariant.

### Alternative 3: 4 MiB+ Chunk Sizes
- **Pros**: Further reduced syscall count.
- **Cons**: Degrades QUIC stream multiplexing, increases cancellation latency, and increases progress bar jitter.
- **Why not**: 512 KiB provides the optimal balance of throughput, responsiveness, and cache residency.

## Consequences

### Positive
- Preparation hashing speed increased by ~27% (from ~2.0 GB/s to ~2.55 GB/s).
- Overlapped disk I/O and network transmission eliminates pipeline bubbles on high-speed networks.
- Bounded memory usage ($1\text{ MiB}$) regardless of total transfer size (tested on multi-hundred megabyte transfers).
- 100% test suite pass rate across all 81 unit, integration, and CLI tests.

### Negative
- Slightly more complex sender streaming loop compared to single-threaded sequential reads.
