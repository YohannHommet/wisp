#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
case "${1:-}" in
  '') exec cargo test --locked --workspace ;;
  --discovery) exec cargo test --locked -p wisp --test cli discovery_two_cli_processes -- --ignored --nocapture ;;
  --release) exec cargo test --locked --release --workspace ;;
  *) echo "Usage: scripts/smoke.sh [--discovery|--release]" >&2; exit 2 ;;
esac
