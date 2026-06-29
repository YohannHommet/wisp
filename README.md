<div align="center">

# ✦ Wisp

**Send files to anyone, encrypted, in one command.**  
End-to-end encrypted · BLAKE3-verified · zero accounts, zero cloud.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.82+-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-Phase%203%20(WAN%2BPAKE)-brightgreen.svg)](docs/THREAT_MODEL.md)

</div>

> A wisp of light that finds its way to you, then vanishes.

---

## Install

Requires the [Rust toolchain](https://rustup.rs) (1.82+).

```bash
git clone https://github.com/YohannHommet/wisp.git
cd wisp
cargo build --release
```

Binaries land at `target/release/wisp` and `target/release/wisp-relay`.  
Add them to your `$PATH` or use the dev runner (`scripts/run.sh`) during development.

---

## Usage

### LAN — same Wi-Fi or Ethernet network

No relay needed. Works on any local network.

**Sender:**
```
$ wisp send photo.jpg

  ✦ wisp ready  (LAN)
    file   photo.jpg (3.4 MB)
    from   192.168.1.42:51023
    blake3 a3f9c12e8b4d7…

    on the other machine, run:
      wisp recv 7-tiger-saturn

  waiting for a receiver…
```

**Receiver** (same LAN, share the code however you like — chat, phone call):
```
$ wisp recv 7-tiger-saturn

  ↘ receiving ━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 3.4 MB/3.4 MB · 580 MB/s · ETA 0s
  ✓ delivered photo.jpg (3.4 MB) — wisp gone.
```

File saves to the current directory. Done — no login, no upload, no account.

---

### WAN — different networks (requires a relay)

The relay brokers the initial connection; it **never sees file content or metadata**.

**Step 1** — run the relay on any machine with a public IP (VPS, home server with open port):
```bash
wisp-relay 7777          # listens on 0.0.0.0:7777
```

**Step 2** — sender passes the relay URL:
```
$ wisp send --relay http://relay.example.com:7777 photo.jpg

  ✦ wisp ready  (WAN via relay)
    file   photo.jpg (3.4 MB)
    public 203.0.113.1:51873
    relay  http://relay.example.com:7777

    on the other machine, run:
      wisp recv --relay http://relay.example.com:7777 7-tiger-saturn
```

**Step 3** — receiver uses the same relay URL and code:
```bash
wisp recv --relay http://relay.example.com:7777 7-tiger-saturn
```

> **NAT note:** WAN mode works when the sender has a reachable public address (VPS, or home router with port forwarding). Two users both behind home NAT may fail — the relay handles discovery only, not data proxying. Full NAT traversal is planned for Phase 4.

---

## CLI reference

### `wisp send`

```
wisp send [OPTIONS] <FILE>

Arguments:
  <FILE>              File to send

Options:
  -n, --name <NAME>   Override the filename shown to the receiver
  -r, --relay <RELAY> WAN relay URL (omit for LAN)
  -v, --verbose       Debug logging
  -h, --help
```

**Examples:**
```bash
wisp send report.pdf
wisp send report.pdf --name "Q3 Report.pdf"   # receiver sees a different name
wisp send report.pdf --relay http://relay.example.com:7777
```

---

### `wisp recv`

```
wisp recv [OPTIONS] <CODE>

Arguments:
  <CODE>              Code shown by the sender (e.g. 7-tiger-saturn)

Options:
  -d, --dir <DIR>     Directory to save into [default: current directory]
  -r, --relay <RELAY> WAN relay URL (must match sender)
  -v, --verbose       Debug logging
  -h, --help
```

**Examples:**
```bash
wisp recv 7-tiger-saturn
wisp recv 7-tiger-saturn --dir ~/Downloads
wisp recv 7-tiger-saturn --relay http://relay.example.com:7777 --dir ~/Downloads
```

If a file with the same name already exists, Wisp saves as `file (1).ext`, `file (2).ext`, etc.

---

### `wisp-relay`

```
wisp-relay [port]     (default 7777)
```

Runs an HTTP rendezvous server. Bind it to `0.0.0.0` so it's reachable from the internet.  
The relay is stateless and structurally blind — it stores only a BLAKE3 commitment of the
pairing code (not the code itself) and the sender's observed public IP:port.

---

## Development

### Dev runner

```bash
./scripts/run.sh send <file>          # auto-builds then sends
./scripts/run.sh recv <code>          # auto-builds then receives
./scripts/run.sh relay [port]         # start local relay
```

Rebuilds automatically if any `.rs` source file is newer than the binary.

### Tests

**Unit + integration tests:**
```bash
cargo test
```

**Smoke tests** (end-to-end, real QUIC transfers):
```bash
bash scripts/smoke.sh             # 10 cases, ~8s
bash scripts/smoke.sh --slow      # +wrong-code timeout test (~28s)
bash scripts/smoke.sh --verbose   # show live wisp output per test
bash scripts/smoke.sh --release   # test release build
```

Smoke test cases: small file, 5 MiB binary, `--name` flag, filename collision,
path-traversal sanitization, SIGINT handling, `.wisp-part` cleanup, WAN relay
transfer, relay HTTP validation.

---

## How it works

```
Sender                    Relay (optional)             Receiver
  │                           │                           │
  │── /pub/{ch}/{fp}/{port} ─→│  (rendezvous only)        │
  │                           │←── /sub/{ch} ─────────────│
  │                           │─── {ip, port, fp} ────────→│
  │←═══════════════════ QUIC + TLS 1.3 (direct) ══════════│
  │         SPAKE2 handshake, then streaming transfer      │
```

- **QUIC / TLS 1.3** — encrypted transport, 1-RTT handshake, ephemeral self-signed cert per session
- **SPAKE2** — password-authenticated key exchange; wrong code = cryptographic rejection, not a timeout
- **mDNS** — LAN discovery uses a BLAKE3 commitment of the code, not the code itself
- **BLAKE3** — streaming integrity check; file is saved under a `.wisp-part` name and atomically renamed only after the hash matches
- **Relay** — blind rendezvous: sees a 16-byte commitment and public IP:port, never file content

---

## Security

See **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** for the full security model.

Short version: the pairing code is the only shared secret. A wrong code fails the SPAKE2 handshake before any file data is exchanged. The relay cannot read or modify transfers (it sees only a hash commitment and IP:port). TLS fingerprint is pinned by the receiver before connecting.

---

## Roadmap

| Phase | Status | Theme |
|---|---|---|
| 1 | ✅ | LAN · QUIC · BLAKE3 verify-before-rename |
| 2 | ✅ | SPAKE2 mutual auth · code commitment in mDNS |
| 3 | ✅ | WAN blind relay · `wisp-relay` binary |
| 4 | planned | NAT traversal · multipath · audit |

---

## Architecture

```
crates/
  wisp-core/      protocol library
    code.rs         short pairing codes
    pake.rs         SPAKE2 mutual auth (RFC 9382)
    discovery.rs    mDNS advertise / find
    relay.rs        HTTP client for WAN rendezvous
    transport.rs    QUIC + ephemeral TLS cert + fingerprint pinning
    transfer.rs     wire protocol + PAKE handshake + verified streaming
  wisp-cli/       `wisp` binary (clap)
  wisp-relay/     `wisp-relay` blind rendezvous server (axum)

scripts/
  run.sh          dev runner (auto-build + send/recv/relay)
  smoke.sh        end-to-end smoke test suite
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).  
Built by [Yohann Hommet](https://github.com/YohannHommet).
