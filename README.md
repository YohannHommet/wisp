<div align="center">

# ✦ Wisp

**Send anything, to anyone, instantly.**
End-to-end encrypted · integrity-verified · zero trust, zero servers.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.82+-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-Phase%203%20(WAN%2BPAKE)-brightgreen.svg)](docs/THREAT_MODEL.md)

</div>

> A wisp of light that finds its way to you, then vanishes.

Wisp is a from-scratch reimagining of peer-to-peer file transfer built on a
simple thesis: the security of a Magic-Wormhole code, the speed of a WireGuard
tunnel, and **zero infrastructure you have to trust** — in a single binary, with
one short code.

## Why Wisp is different

Plenty of tools are "secure and fast." Wisp's moat is the *combination* the
incumbents don't ship together:

- **Verified streaming.** Integrity is checked with BLAKE3 as bytes arrive, and
  Wisp **never writes an unverified byte under the final filename**. Data lands
  in a `.wisp-part` file and is atomically renamed only after verification.
- **QUIC transport.** Built on QUIC (TLS 1.3): multiplexed, no head-of-line
  blocking, fast 1-RTT handshakes, connection migration.
- **Zero trust infrastructure.** Pairing is a short human code. No accounts, no
  PKI, no server that can read your data. The optional relay is structurally
  blind — it sees only a BLAKE3 commitment of the code and never touches file
  content or metadata.
- **One static binary.** No runtime, no daemon, no app store.

## Install

Requires the [Rust toolchain](https://rustup.rs) (1.82+).

```bash
git clone https://github.com/YohannHommet/wisp.git
cd wisp
cargo build --release
# binary at target/release/wisp
```

## Quick start

### LAN (same network)

```bash
# sender
wisp send report.pdf

# receiver (same LAN)
wisp recv 7-tiger-saturn
```

### WAN (different networks)

Run a relay somewhere public (VPS, home server with open port):

```bash
wisp-relay 7777
```

Then:

```bash
# sender
wisp send --relay http://relay.example.com:7777 report.pdf

#   ✦ wisp ready  (WAN via relay)
#     file   report.pdf (4.21 MB)
#     public 203.0.113.1:51873
#     relay  http://relay.example.com:7777
#
#     on the other machine, run:
#       wisp recv --relay http://relay.example.com:7777 7-tiger-saturn

# receiver (anywhere)
wisp recv --relay http://relay.example.com:7777 7-tiger-saturn

#   ↘ receiving ━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.21 MB/4.21 MB · 612 MB/s · ETA 0s
#   ✓ verified · 4.21 MB · saved to ./report.pdf
```

The relay only brokers the connection — it never sees file content or metadata.

## Security status — read this

Wisp is built in honest phases. **Phase 3 (current)** adds WAN reach via a
structurally blind relay: the relay sees only a 16-byte BLAKE3 commitment of
the code and the TLS fingerprint — never file content or metadata. The direct
QUIC connection (SPAKE2-authenticated, TLS-encrypted) is established between
sender and receiver; the relay's only job is initial rendezvous and public-IP
discovery.

Phase 3 works when at least one party has a reachable public address (VPS,
home router with port forwarding). Full hole-punching for symmetric NAT is
planned for Phase 3.5.

👉 The full, phase-by-phase security contract lives in
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**. We never claim a property we
have not shipped.

## Roadmap

| Phase | Theme | Highlights |
| --- | --- | --- |
| **1** ✅ | LAN, verified | mDNS discovery · QUIC/TLS · BLAKE3 verify-before-rename |
| **2** ✅ | Authenticated channel | SPAKE2 (RFC 9382) · code commitment in mDNS · encrypted metadata |
| **3** ✅ | WAN | Blind relay rendezvous · observed public IP · `wisp-relay` binary |
| **4** | Speed & assurance | multipath bonding · FEC · fuzzing · formal proof · audit |

See **[docs/BRANDING.md](docs/BRANDING.md)** for the brand book and
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** for the security model.

## Architecture

```
crates/
  wisp-core/      the protocol library
    code.rs       short pairing codes (PAKE password)
    pake.rs       SPAKE2 mutual authentication (RFC 9382)
    discovery.rs  mDNS advertise / find (LAN, code commitment)
    relay.rs      HTTP client for WAN rendezvous (--relay)
    transport.rs  QUIC + self-signed cert + fingerprint pinning
    transfer.rs   WSP/1 wire protocol + PAKE handshake + verified streaming
  wisp-cli/       the `wisp` binary (clap, --relay flag)
  wisp-relay/     the `wisp-relay` blind rendezvous server (axum)
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Built by [Yohann Hommet](https://github.com/YohannHommet).
