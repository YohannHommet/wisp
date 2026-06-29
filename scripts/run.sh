#!/usr/bin/env bash
# Wisp dev runner — auto-builds if needed, then runs the requested command.
#
# Usage:
#   ./scripts/run.sh send <file> [--name NAME] [--relay URL]
#   ./scripts/run.sh recv <code> [--dir DIR] [--relay URL]
#   ./scripts/run.sh relay [port]        # start relay (default port 7777)
#
# Examples:
#   ./scripts/run.sh send test.bin
#   ./scripts/run.sh recv 7-tiger-saturn
#   ./scripts/run.sh relay 7777

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BIN="./target/debug/wisp"
RELAY_BIN="./target/debug/wisp-relay"

# ── auto-build if binary is missing or source is newer ───────────────────────
needs_build() {
  local bin="$1"; shift
  [ ! -x "$bin" ] && return 0
  # rebuild if any source file is newer than the binary
  find crates -name '*.rs' -newer "$bin" | grep -q . 2>/dev/null
}

if needs_build "$BIN" || needs_build "$RELAY_BIN"; then
  echo "  building…"
  cargo build --bin wisp --bin wisp-relay 2>&1 | grep -E '^error|Compiling|Finished' || true
  echo
fi

# ── dispatch ─────────────────────────────────────────────────────────────────
cmd="${1:-}"
shift || true

case "$cmd" in
  send)
    [ $# -eq 0 ] && { echo "Usage: $0 send <file> [--name NAME] [--relay URL]"; exit 1; }
    exec "$BIN" send "$@"
    ;;
  recv)
    [ $# -eq 0 ] && { echo "Usage: $0 recv <code> [--dir DIR] [--relay URL]"; exit 1; }
    exec "$BIN" recv "$@"
    ;;
  relay)
    port="${1:-7777}"
    echo "  starting relay on port $port  (Ctrl-C to stop)"
    exec "$RELAY_BIN" "$port"
    ;;
  ""|help|-h|--help)
    echo "Usage:"
    echo "  $0 send <file> [--name NAME] [--relay URL]"
    echo "  $0 recv <code> [--dir DIR]  [--relay URL]"
    echo "  $0 relay [port]             (default 7777)"
    ;;
  *)
    echo "Unknown command: $cmd"; exit 1 ;;
esac
