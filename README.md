# Wisp

[![CI](https://github.com/YohannHommet/wisp/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/YohannHommet/wisp/actions/workflows/ci.yml)
[![Pages](https://github.com/YohannHommet/wisp/actions/workflows/pages.yml/badge.svg?branch=develop)](https://yohannhommet.github.io/wisp/)
[![Documentation & Demo](https://img.shields.io/badge/website%20%26%20demo-interactive-06b6d4)](https://yohannhommet.github.io/wisp/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Threat Model](https://img.shields.io/badge/security-threat%20model-8b5cf6)](docs/THREAT_MODEL.md)

Send a file between two computers on the same network. No account, browser, cloud storage, or server to configure.

> 🌐 **Interactive Demo & Architecture Explorer**: Test real-time transfer scenarios and view the authenticated QUIC protocol flow at **[yohannhommet.github.io/wisp](https://yohannhommet.github.io/wisp/)**.

Wisp 0.2 is a terminal app for one file at a time. Install it on **both computers**, use the same Wi-Fi or Ethernet network, and keep both commands open until they finish. To send a folder or several files, create an archive first.

## Installation

Install Wisp on **both computers**:

### One-line installer (Recommended)

**Linux & macOS** (x86_64, ARM64 / Apple Silicon):
```sh
curl -fsSL https://raw.githubusercontent.com/YohannHommet/wisp/develop/scripts/install.sh | bash
```

**Windows PowerShell** (x64):
```powershell
irm https://raw.githubusercontent.com/YohannHommet/wisp/develop/scripts/install.ps1 | iex
```

*Checksums (`SHA256SUMS`) are verified before installation. Binaries are installed to `~/.local/bin` or `%LOCALAPPDATA%\Wisp\bin` without requiring administrator or root privileges.*

### From source with Cargo

With Rust 1.88+ installed:
```sh
cargo install --locked --path crates/wisp-cli
wisp --version
```

See the [Platform setup instructions](docs/USER_GUIDE.md#installation-and-path) for custom PATH and version overrides.

## Your first transfer

**1. On the sending computer**, choose a file:

```sh
wisp send "report.pdf"
```

Wisp prints a receive command containing a fresh code. Leave this terminal open.

**2. On the receiving computer**, paste that command and add a destination:

```text
wisp recv CODE --dir ./received
```

Replace `CODE` with the complete code printed by the sender. Wisp creates `received` if needed. Without `--dir`, it uses your configured download directory, or the terminal's current directory when no directory is configured.

**3. Wait for confirmation** on both computers:

```text
Receiver: Saved and verified: ...
Sender:   Delivered and verified: ...
```

These labels show which terminal to check; they are not commands. The receiver prints the actual saved path. Existing files are preserved: a repeated `report.pdf` becomes `report (1).pdf`.

If discovery fails, [connect using the sender's address](#when-discovery-cannot-find-the-sender).

## Everyday use

Replace `CODE` below with the fresh code from the sender. Quote paths containing spaces.

```sh
wisp send photo.jpg
wisp send report.pdf --name 'Quarterly Report.pdf'
wisp recv CODE --dir ~/Downloads
wisp recv CODE --max-size 500MiB
```

A code contains a public eight-digit session identifier plus **four secret words**. It is single-use and, by default, expires after five minutes of waiting. Share it privately with the intended receiver. Authentication failure ends that session; run `send` again rather than reusing the code.

Received files never overwrite an existing destination. A collision saves as `report (1).pdf`, then `report (2).pdf`. Incomplete or invalid transfers are removed on ordinary errors and handled cancellation. Wisp saves regular files only and does not resume interrupted transfers.

## CLI usage

The command has two actions:

```text
wisp send FILE [OPTIONS]
wisp recv CODE [OPTIONS]
```

Start with `wisp send FILE`. It prints the complete one-use code and a ready-to-paste `wisp recv ...` command. On the other computer, paste that command and optionally add `--dir DIRECTORY`.

Use these options only when you need them:

| Need | Option |
|---|---|
| Choose the destination directory | `recv --dir DIRECTORY` |
| Bypass automatic discovery | `recv --address IPv4:PORT` |
| Choose the sender's network interface | `send --bind IPv4` |
| Avoid multicast discovery | `send --no-discovery` (also requires `recv --address`) |
| Keep the code valid longer | `send --wait SECONDS` |
| Reject files above a limit | `recv --max-size 500MiB` |
| Send under another filename | `send --name NAME` |
| Ignore a broken user config | `--no-config` |
| Script the transfer | `--json` |

Run `wisp --help`, `wisp send --help`, or `wisp recv --help` for the full option list. `receive` is an alias for `recv`. A code is single-use; after authentication, expiry, cancellation, or a failed transfer, start `send` again for a fresh code.

For source checkouts, the Makefile provides shortcuts: `make help`, `make build`, `make install`, `make test`, `make check`, and `make discovery`. `make run ARGS="send ./photo.jpg"` runs the checkout without installing it.

## When discovery cannot find the sender

Both computers need a reachable IPv4 connection, usually the same Wi-Fi or Ethernet network. Guest networks, client isolation, VPN routing and firewalls can block discovery or transfers.

The sender always prints its address. Replace the example address below with that address and use the full current code to bypass automatic discovery:

```bash
wisp recv CODE --address 192.168.1.42:51023
```

On a computer with multiple network interfaces, select the LAN address explicitly:

```bash
wisp send report.pdf --bind 192.168.1.42
```

For a fixed firewall rule or a multicast-free network:

```bash
wisp send report.pdf --bind 192.168.1.42 --port 51023 --no-discovery
wisp recv CODE --address 192.168.1.42:51023
```

Allow the sender's UDP port and, for automatic discovery, mDNS on UDP 5353. Wisp never changes firewall rules. An explicit address does not bypass a firewall or network isolation.

## Configuration and automation

Configuration is optional. Run `wisp --help` and see the [user guide](docs/USER_GUIDE.md) for paths, timeouts, exit codes and JSON events.

```bash
wisp --no-config send report.pdf
wisp --json send report.pdf
wisp --json recv CODE --dir ./received
```

JSON mode emits one object per line, including the actual ready code and a final verified receipt. Treat this output as sensitive: the ready event contains the pairing secret. Human progress goes to stderr and is disabled when stderr is not a terminal. Runtime failures have structured JSON errors; argument parsing errors use the normal CLI diagnostic and exit code 2.

## Security

Transfers use QUIC/TLS encryption, channel-bound SPAKE2 authentication and BLAKE3 integrity checks. The sender reports success only after receiving confirmation of a verified save. Read the [security model](docs/THREAT_MODEL.md) for guarantees and limits; this implementation has not had an independent security audit.

## Development

To build without installing:

```sh
cargo build --locked --release --bin wisp
./target/release/wisp --help
```

On Windows PowerShell, use `.\target\release\wisp.exe --help` instead.

Run the checks:

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
