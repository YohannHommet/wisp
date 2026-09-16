# Wisp

Send a file between two computers on the same network. No account, browser, cloud storage, or server to configure.

```text
# Computer A
wisp send report.pdf

  wisp recv 48291370-amber-river-lunar-moss

# Computer B: paste the command printed by Computer A
wisp recv 48291370-amber-river-lunar-moss

Saved and verified: /home/you/report.pdf (24576 bytes)
```

The example code is illustrative; use the fresh code printed by your sender. Both computers must keep Wisp running until the transfer finishes.

Wisp uses QUIC/TLS encryption, channel-bound SPAKE2 authentication and BLAKE3 integrity checks. The sender reports **delivered and verified** only after receiving confirmation that the receiver verified and saved the file. See the [security model](docs/THREAT_MODEL.md) for the guarantees and limits; this implementation has not had an independent security audit.

## Install

From this checkout, with Rust 1.88 or newer:

```bash
cargo install --locked --path crates/wisp-cli
```

Or build without installing:

```bash
cargo build --locked --release --bin wisp
./target/release/wisp --help
```

Published CLI releases provide Linux x64/ARM64 binaries, a universal macOS binary, and a Windows x64 executable alongside `SHA256SUMS`. Verify the downloaded binary against that file. The [Unix installer](scripts/install.sh) and [PowerShell installer](scripts/install.ps1) perform this verification before installation. They require a published release with checksums; building this checkout does not publish a release.

The Unix installer defaults to `~/.local/bin`; Windows defaults to `%LOCALAPPDATA%\Wisp\bin`. Neither changes your shell configuration or requests administrator privileges. Set `WISP_INSTALL_DIR` to change the destination and `WISP_VERSION=v0.2.0` to select a published tag. The binaries are not platform code-signed or notarized.

## Everyday use

```bash
wisp send photo.jpg
wisp send report.pdf --name 'Quarterly Report.pdf'
wisp recv <code> --dir ~/Downloads
wisp recv <code> --max-size 500MiB
```

A code contains a public eight-digit session identifier plus **four secret words**. It is single-use and expires after five minutes of waiting. Authentication failure ends that session; run `send` again rather than reusing the code.

Received files never overwrite an existing destination. A collision saves as `report (1).pdf`, then `report (2).pdf`. Incomplete or invalid transfers are removed on ordinary errors and handled cancellation. Wisp saves regular files only: archive a folder or multiple files first.

## When discovery cannot find the sender

Both computers need a reachable IPv4 connection, usually the same Wi-Fi or Ethernet network. Guest networks, client isolation, VPN routing and firewalls can block discovery or transfers.

The sender always prints its address. Use it to bypass mDNS while keeping code authentication:

```bash
wisp recv <code> --address 192.168.1.42:51023
```

On a computer with multiple network interfaces, select the LAN address explicitly:

```bash
wisp send report.pdf --bind 192.168.1.42
```

For a fixed firewall rule or a multicast-free network:

```bash
wisp send report.pdf --bind 192.168.1.42 --port 51023 --no-discovery
wisp recv <code> --address 192.168.1.42:51023
```

Allow the sender's UDP port and, for automatic discovery, mDNS on UDP 5353. Wisp never changes firewall rules. An explicit address does not bypass a firewall or network isolation.

## Configuration and automation

Configuration is optional. Run `wisp --help` and see the [user guide](docs/USER_GUIDE.md) for paths, timeouts, exit codes and JSON events.

```bash
wisp --no-config send report.pdf
wisp --json send report.pdf
wisp --json recv <code> --dir ./received
```

JSON mode emits one object per line, including the actual ready code and a final verified receipt. Treat this output as sensitive: the ready event contains the pairing secret. Human progress goes to stderr and is disabled when stderr is not a terminal. Runtime failures have structured JSON errors; argument parsing errors use the normal CLI diagnostic and exit code 2.

## Development

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
bash scripts/smoke.sh --discovery  # needs an IPv4 interface and multicast
```

Tests use real QUIC sockets, hostile peers and actual CLI processes. Automatic discovery is an explicit integration test because multicast availability varies by environment. CI tests Linux, macOS and Windows, checks the minimum Rust version, and audits dependencies. Tagged builds create a **draft** CLI release only after checks pass.

See [architecture](docs/ARCHITECTURE.md), [release checks](docs/RELEASING.md), and [changes](CHANGELOG.md).

## Upgrading from the prototype

Wisp 0.2 is CLI-only. The unfinished desktop interface, internet rendezvous relay and persistent-device pairing have been removed. Upgrade **both computers**: WSP/2, discovery records and codes are incompatible with 0.1.

Remove old `default_relay` and `trusted_peers` configuration fields, or use `--no-config`. Old user configuration and identity files are never automatically deleted. Wisp 0.2 does not load the old persistent keys.

Apache-2.0. Built by [Yohann Hommet](https://github.com/YohannHommet).
