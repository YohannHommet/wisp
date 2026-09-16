# Release assurance

A refactor and passing local tests do not establish independent security assurance or validate every operating system and network. Use the following checks before publishing.

## Automated gates

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --release --workspace
cargo build --locked --release --bin wisp
cargo audit --deny warnings
python3 scripts/test_install.py
```

CI runs portable tests on Linux, Apple Silicon macOS, Intel macOS and Windows x64, plus a Rust 1.88 check and advisory audit. It validates installer syntax. Host tests use loopback sockets; multicast discovery is a separately selected integration test:

```bash
bash scripts/smoke.sh --discovery
```

The `fuzz` workspace is isolated from normal builds. With cargo-fuzz installed, run from `fuzz/`:

```bash
cargo +nightly fuzz run fuzz_wire -- -max_total_time=60
```

This target covers actual code parsing and filename sanitization. Protocol framing is exercised by deterministic hostile-peer tests; the fuzz target is not a comprehensive wire-protocol fuzzer.

## Physical-device checks

On at least two real computers, exercise automatic discovery and explicit-address transfer across Linux/macOS/Windows combinations. Verify a small file, an empty file, a large binary, a Unicode filename and a collision. Confirm actual saved bytes/checksums on the destination, not just terminal success.

Check a VPN plus LAN interface using `--bind`, firewall-denied traffic, guest-network isolation, Wi-Fi disconnection, Ctrl+C on each side, destination storage failure, and a wrong secret with the correct public locator. Authentication failure must require a new sending session. Interrupted receives must not overwrite old files. Check output in an ordinary terminal and redirected JSON mode.

Test installation from a candidate release into a temporary user directory. Confirm that a mismatched or missing checksum refuses installation and preserves the existing binary. Windows and macOS binaries are not code-signed/notarized by this workflow: check how the OS presents them and document distribution requirements rather than bypassing protections automatically.

## Drafting and publishing

Update the workspace version and changelog, merge only after required checks pass, and create the corresponding `vX.Y.Z` tag. The release workflow checks tag/version agreement, runs CI, tests native release targets and builds Linux musl x64/ARM64, universal macOS, and Windows x64 artifacts.

It collects all successful artifacts, creates `SHA256SUMS`, and creates one **draft** GitHub release. Review its assets and complete physical-device/installer checks before publishing it. No release is created merely by building locally.

Checksums detect a corrupted or mismatched download; they do not independently authenticate the release author if the hosting account is compromised. Publishing signed/notarized binaries or provenance attestations would require separate credentials and release policy.

An independent review of the SPAKE2/TLS channel-binding composition is still recommended before promoting Wisp for sensitive production deployments. Do not describe an automated test run as a security audit.
