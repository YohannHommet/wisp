# LAN CLI refactor status

Active branch: `refactor/lan-cli`. Scope: restore the original one-file LAN CLI and retire the unfinished desktop, WAN relay and persistent-device-pairing experiments. No release has been published and no user configuration was removed.

Implemented: typed independent public-locator/four-word codes, single-attempt sessions, explicit core options/events, verified-save receipts, safe private temporary files and collision publication, handled cancellation, direct IPv4 fallback, interface/port selection, receive limits, JSON output, strict configuration, regression tests, CLI-only gated draft releases and checksum-verifying installers.

Verification completed (final source checked on 2026-09-17):

- Formatting and Clippy with warnings denied passed. All 31 portable Rust tests passed in both debug and optimized-release profiles; the separate multicast discovery test also passed. The release CLI build succeeded.
- Automatic discovery passed using two actual CLI processes on this host's LAN interface.
- On 2026-09-10, the dependency audit initially failed with RUSTSEC-2026-0185, three other advisory warnings and a yanked version. Dependencies were updated; the subsequent audit exited 0 with no findings (217 locked dependencies, 1243 advisories loaded).
- Rust 1.88 `cargo check --locked --workspace --all-targets` passed against the updated lockfile on 2026-09-10. The temporary audit binary and Rust toolchain were no longer present on 2026-09-17, so those earlier checks were not repeated; CI retains both gates.
- A non-UTF-8 destination JSON crash was reproduced and fixed; its subprocess regression passes.
- Installer directory-target false success was reproduced and fixed; all six fixture-based installer tests pass.
- Review found a Windows release-step exit-code masking issue; tests and build are now separate workflow steps.
- Definition-of-done hygiene script and whitespace checks pass.

Failed stdout handling was reproduced and fixed: human and JSON modes terminate with an actionable error instead of silently waiting. The final suite includes that regression. Implementation and local verification are complete; the reviewed changes are committed on the branch named above. The unrelated untracked `wisp-architecture.*` artifacts were left untouched.

Unverified externally: execution on physical pairs of computers, Windows/macOS runtime and installer behavior, hosted GitHub Actions runs, platform signing/notarization, and an independent protocol security audit. CI and docs specify those checks; local Linux tests do not establish them.
