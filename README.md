<div align="center">

# ✦ Wisp

**Send anything, to anyone, instantly.**
End-to-end encrypted · integrity-verified · zero trust, zero servers.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.82+-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-Phase%201%20(LAN)-yellow.svg)](docs/THREAT_MODEL.md)

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
  PKI, no server that can read your data. *(PAKE-authenticated channel lands in
  Phase 2; see the roadmap.)*
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

On the **sending** machine:

```bash
wisp send report.pdf
```

```
  ✦ wisp ready
    file   report.pdf (4.21 MB)
    from   192.168.1.42:51873
    blake3 9f2c1a0b7d4e5f6a…

    on the other machine, run:
      wisp recv 7-tiger-saturn

  waiting for a receiver…
```

On the **receiving** machine (same LAN):

```bash
wisp recv 7-tiger-saturn
```

```
  ↘ receiving ━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.21 MB/4.21 MB · 612 MB/s · ETA 0s
  ✓ verified · 4.21 MB · saved to ./report.pdf
```

## Security status — read this

Wisp is built in honest phases. **Phase 1 (current)** protects content against a
*passive* eavesdropper on the LAN (QUIC/TLS 1.3) and guarantees integrity
(BLAKE3 verify-before-rename), but it does **not** yet defend against an
*active* on-LAN attacker spoofing mDNS, and metadata (filename, size) is
advertised in cleartext.

👉 The full, phase-by-phase security contract lives in
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**. We never claim a property we
have not shipped.

## Roadmap

| Phase | Theme | Highlights |
| --- | --- | --- |
| **1** ✅ | LAN, verified | mDNS discovery · QUIC/TLS · BLAKE3 verify-before-rename |
| **2** | Authenticated channel | CPace PAKE · channel binding · encrypted metadata |
| **3** | WAN | DHT rendezvous · NAT hole-punching · **blind relay** |
| **4** | Speed & assurance | multipath bonding · FEC · fuzzing · formal proof · audit |

See **[docs/BRANDING.md](docs/BRANDING.md)** for the brand book and
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** for the security model.

## Architecture

```
crates/
  wisp-core/      the protocol library
    code.rs       short pairing codes (future PAKE password)
    discovery.rs  mDNS advertise / find
    transport.rs  QUIC + self-signed cert + fingerprint pinning
    transfer.rs   WSP/1 wire protocol + verified streaming
  wisp-cli/       the `wisp` binary (clap)
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Built by [Yohann Hommet](https://github.com/YohannHommet).
