# Wisp CLI user guide

## Transfer a file

Install Wisp 0.2 or newer on both computers. Connect them to the same reachable IPv4 network.

On the sender:

```bash
wisp send ./photo.jpg
```

Copy the printed `wisp recv …` command and run it on the receiver. The sender stays open while waiting. By default, the receiver saves to its current directory. Use `--dir ~/Downloads` to choose another directory. Files with colliding names get numbered suffixes; existing files and symlinks are not overwritten.

The sender finishes with `Delivered and verified` only after the receiver confirms a verified save. The receiver prints the actual saved path. If delivery is unconfirmed, check that path before retrying.

To send multiple files or a folder, create an archive first. Wisp does not preserve executable permissions or extended attributes. An empty file is supported.

## Commands

```text
wisp [GLOBAL OPTIONS] send [OPTIONS] <FILE>
wisp [GLOBAL OPTIONS] recv [OPTIONS] <CODE>
```

`receive` is an alias for `recv`. Global options may also follow the subcommand.

| Option | Meaning |
|---|---|
| `send --name NAME` | Override the received filename; sanitized to a portable single name |
| `send --bind IPv4` | Select the local interface; otherwise use the OS-selected local IPv4 |
| `send --port PORT` | Select a UDP port; default 0 allocates one |
| `send --no-discovery` | Do not advertise; receiver must use `--address` |
| `send --wait SECONDS` | Code waiting lifetime, 1–3600 seconds; default 300 |
| `recv --dir DIRECTORY` | Choose the destination directory |
| `recv --address IPv4:PORT` | Bypass mDNS and connect directly, still using code authentication |
| `recv --max-size SIZE` | Reject files above SIZE; bytes or integer KiB/MiB/GiB/TiB; default 1 TiB |
| `--timeout SECONDS` | Override discovery, authentication and network I/O timeouts, 1–3600 seconds |
| `--config PATH` | Require and load a particular TOML file |
| `--no-config` | Ignore the platform's user configuration |
| `--json` | Emit newline-delimited JSON to stdout |
| `--quiet` / `-q` | Hide progress/status but retain the code, outcome and warnings |
| `--verbose` / `-v` | Network diagnostics on stderr |
| `--help` / `--version` | Show usage/version without starting a transfer |

A pairing code is eight digits and four words, separated by hyphens. Pasted leading/trailing whitespace and ASCII case are normalized. Missing words, unknown words and old three-part codes are rejected. Share the complete code through a trusted channel; the four words are the authentication secret.

## Optional configuration

The default is the platform configuration directory plus `wisp/config.toml`:

- Linux: `$XDG_CONFIG_HOME/wisp/config.toml`, or `~/.config/wisp/config.toml`.
- macOS: `~/Library/Application Support/wisp/config.toml`.
- Windows: `%APPDATA%\wisp\config.toml`.

```toml
default_download_dir = "~/Downloads"

[timeouts]
pake = 15
discovery = 20
block_transfer = 30
wait = 300
```

All timeout values must be integer seconds from 1 to 3600. Missing values use defaults. CLI flags override configuration. The destination falls back to the current directory. `~` and `~/…` expand against the user's home directory. Configuration paths are not expanded through arbitrary environment-variable substitution.

Missing default configuration is fine; malformed configuration, unknown fields and an explicitly requested missing file are errors. Nothing is silently rewritten. Wisp 0.2 rejects legacy `default_relay`/`trusted_peers` fields with migration guidance. `WISP_RELAY` is no longer used. No configuration is loaded implicitly inside the protocol library.

## Troubleshooting

**No sender found:** keep the sending command open, check that both computers run Wisp 0.2 or newer, and copy the whole code. Try the `--address` shown by the sender if multicast is blocked.

**Wrong network address:** a VPN may be the default route. Use `send --bind` with the LAN IPv4 address. IPv6-only networks are not currently supported.

**Cannot reach sender:** allow inbound UDP on the sender's selected port. Automatic discovery also needs UDP 5353. Guest Wi-Fi/client isolation can block device-to-device traffic even when both computers use the same access point. A direct address cannot bypass those policies.

**Authentication failed:** stop and run a new `send`. Each code permits one incoming attempt and cannot be safely retried indefinitely. Wisp never falls back to unauthenticated transfer.

**Source changed:** stop editing or generating the file before sending it. Wisp checks the bytes it sends against the prepared checksum.

**Receive limit or disk error:** choose sufficient storage, or set a deliberate `--max-size`. Wisp cannot reserve disk capacity in advance; a full disk fails the transfer without a success receipt.

**Delivery unconfirmed:** the receiver might have saved the file but lost the acknowledgement. Check the destination before retrying; another successful receive would create a numbered copy.

**Interrupted transfer:** Ctrl+C cancels; Unix SIGTERM is also handled. Incomplete temporary files are cleaned up. After SIGKILL, a crash or power loss, `.wisp-*.part` files may remain. Remove only abandoned partial files when no transfer is active. A completed file is retained if interruption happens after publication.

## Automation

```bash
wisp --json --no-config send ./report.pdf
wisp --json --no-config recv <code> --dir ./received
```

Each stdout line is a JSON object. Event names include `preparing`, `ready`, `discovering`, `connecting`, `authenticating`, `progress`, `verifying`, `awaiting_receipt`, `warning`, `completed`, and `error`. Progress is throttled; do not assume one event per chunk. `ready` provides the code, sender address, discovery status, size and waiting lifetime. `completed.receipt` includes the saved name, byte count and BLAKE3 hash; receivers also include `saved_to`. JSON paths are display strings: invalid native UTF-8 bytes are replaced with U+FFFD, while the Rust API retains the exact `PathBuf`.

Runtime errors include `message` and `exit_code`. CLI argument errors occur before the runtime event stream: they use normal stderr diagnostics and exit 2, even with `--json`. The code appears in `ready`; do not retain or publish that output as telemetry. Debug logs use stderr. If stdout fails, Wisp stops with exit 1 and reports the output failure on stderr; a file already saved is retained.

| Exit code | Meaning |
|---|---|
| 0 | Successful local save or confirmed sender delivery |
| 1 | Configuration, file, network, authentication or protocol error |
| 2 | Invalid command-line arguments |
| 130 | Cancelled with Ctrl+C |
| 143 | Terminated with SIGTERM on Unix |
