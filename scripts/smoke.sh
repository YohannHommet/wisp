#!/usr/bin/env bash
# Wisp smoke test suite — automated manual testing
#
# Usage:
#   bash scripts/smoke.sh             # debug build, fast tests
#   bash scripts/smoke.sh --release   # release build
#   bash scripts/smoke.sh --slow      # also run slow tests (20s+ each)
#   bash scripts/smoke.sh --verbose   # show wisp output live (useful for debugging)
#   WISP=./my-wisp bash scripts/smoke.sh

set -uo pipefail

# ── flags ────────────────────────────────────────────────────────────────────
RELEASE=0; SLOW=0; VERBOSE=0
for arg in "$@"; do
  case "$arg" in
    --release) RELEASE=1 ;;
    --slow)    SLOW=1 ;;
    --verbose) VERBOSE=1 ;;
    -h|--help)
      echo "Usage: $0 [--release] [--slow] [--verbose]"
      echo "  --release   use release binaries"
      echo "  --slow      include tests with long timeouts"
      echo "  --verbose   show wisp output live (good for debugging)"
      exit 0 ;;
  esac
done

if [ $RELEASE -eq 1 ]; then
  WISP="${WISP:-./target/release/wisp}"
  RELAY="${RELAY:-./target/release/wisp-relay}"
  CARGO_FLAGS="--release"
else
  WISP="${WISP:-./target/debug/wisp}"
  RELAY="${RELAY:-./target/debug/wisp-relay}"
  CARGO_FLAGS=""
fi

RELAY_PORT=17777
RELAY_URL="http://127.0.0.1:$RELAY_PORT"

# ── state ────────────────────────────────────────────────────────────────────
PASS=0; FAIL=0; SKIP=0
WORK=$(mktemp -d)
SPID=; RPID=

cleanup() {
  [ -n "$SPID" ] && kill "$SPID" 2>/dev/null || true; SPID=
  [ -n "$RPID" ] && kill "$RPID" 2>/dev/null || true; RPID=
  jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ── colors ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  CLR_G='\033[0;32m'; CLR_R='\033[0;31m'; CLR_Y='\033[0;33m'
  CLR_B='\033[1m';    CLR_D='\033[2m';     CLR_N='\033[0m'
else
  CLR_G=''; CLR_R=''; CLR_Y=''; CLR_B=''; CLR_D=''; CLR_N=''
fi

ok()      { printf "${CLR_G}  ✓${CLR_N}  %-56s ${CLR_D}%ss${CLR_N}\n" "$1" "$2"; ((PASS++)); }
fail()    { printf "${CLR_R}  ✗${CLR_N}  %s\n" "$1"; ((FAIL++)); }
skip()    { printf "${CLR_Y}  ○${CLR_N}  %s ${CLR_D}(skipped)${CLR_N}\n" "$1"; ((SKIP++)); }
section() { printf "\n${CLR_B}▸ %s${CLR_N}\n" "$1"; }

# Redirect: silent in normal mode, live in --verbose
Q() { if [ $VERBOSE -eq 1 ]; then "$@"; else "$@" >/dev/null 2>&1; fi; }

# ── helpers ──────────────────────────────────────────────────────────────────

# Poll file for regex; timeout = N * 0.1s (default 150 = 15s)
wait_for() {
  local file="$1" pat="$2" lim="${3:-150}" i=0
  while (( i < lim )); do
    grep -qE "$pat" "$file" 2>/dev/null && return 0
    sleep 0.1; (( i++ ))
  done
  return 1
}

# Start sender in background; sets SPID and CODE. Extra args forwarded.
launch_sender() {
  local src="$1" out="$2"; shift 2
  if [ $VERBOSE -eq 1 ]; then
    "$WISP" send "$src" "$@" | tee "$out" &
  else
    "$WISP" send "$src" "$@" >"$out" 2>/dev/null &
  fi
  SPID=$!
  if ! wait_for "$out" 'wisp recv' 150; then
    fail "sender: pairing code not printed within 15s"
    SPID=; return 1
  fi
  CODE=$(grep 'wisp recv' "$out" | awk '{print $NF}' | head -1)
  [ -n "$CODE" ]
}

stop_sender() {
  if [ -n "$SPID" ]; then
    kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null || true; SPID=
  fi
}

# ── repo root ────────────────────────────────────────────────────────────────
cd "$(dirname "${BASH_SOURCE[0]}")/.." && REPO_ROOT="$(pwd)"

# ── build ────────────────────────────────────────────────────────────────────
section "Build"
t=$SECONDS
# shellcheck disable=SC2086
if cargo build $CARGO_FLAGS --bin wisp --bin wisp-relay 2>&1 | grep -E '^error' | head -5; then
  fail "cargo build (see errors above)"; exit 1
fi
if [ ! -x "$WISP" ] || [ ! -x "$RELAY" ]; then
  fail "binaries not found after build: $WISP / $RELAY"; exit 1
fi
ok "cargo build" $((SECONDS - t))

# ── LAN transfer ─────────────────────────────────────────────────────────────
section "LAN transfer"

# 1 — small file, byte-exact
t=$SECONDS
TD=$(mktemp -d "$WORK/XXXXXX"); src="$TD/hello.txt"; dst="$TD/recv"
printf 'hello wisp smoke test!\n%.0s' {1..80} >"$src"
if launch_sender "$src" "$TD/s.out"; then
  if Q "$WISP" recv "$CODE" --dir "$dst" && cmp -s "$src" "$dst/hello.txt"; then
    ok "small text file — byte-exact" $((SECONDS - t))
  else
    fail "small file (transfer failed or content mismatch)"
  fi
fi
stop_sender

# 2 — 5 MiB binary, BLAKE3 verified internally by wisp
t=$SECONDS
TD=$(mktemp -d "$WORK/XXXXXX"); src="$TD/big.bin"; dst="$TD/recv"
dd if=/dev/urandom bs=1024 count=5120 of="$src" 2>/dev/null
if launch_sender "$src" "$TD/s.out"; then
  if Q "$WISP" recv "$CODE" --dir "$dst" && cmp -s "$src" "$dst/big.bin"; then
    ok "5 MiB binary — BLAKE3 verified + byte-exact" $((SECONDS - t))
  else
    fail "5 MiB binary (transfer failed or content mismatch)"
  fi
fi
stop_sender

# 3 — custom display name via --name
t=$SECONDS
TD=$(mktemp -d "$WORK/XXXXXX"); src="$TD/original.dat"; dst="$TD/recv"
echo "custom name test" >"$src"
if launch_sender "$src" "$TD/s.out" --name "renamed.dat"; then
  if Q "$WISP" recv "$CODE" --dir "$dst" && [ -f "$dst/renamed.dat" ]; then
    ok "--name flag — file received as 'renamed.dat'" $((SECONDS - t))
  else
    fail "--name flag (file not renamed or transfer failed)"
  fi
fi
stop_sender

# 4 — filename collision → unique suffix
t=$SECONDS
TD=$(mktemp -d "$WORK/XXXXXX"); src="$TD/data.txt"; dst="$TD/recv"
mkdir -p "$dst"; echo "pre-existing" >"$dst/data.txt"; echo "new version" >"$src"
if launch_sender "$src" "$TD/s.out"; then
  if Q "$WISP" recv "$CODE" --dir "$dst" && [ -f "$dst/data (1).txt" ]; then
    ok "filename collision → 'data (1).txt'" $((SECONDS - t))
  else
    fail "filename collision (expected 'data (1).txt' in $dst)"
  fi
fi
stop_sender

# 5 — path-traversal display name → sanitized to just filename
t=$SECONDS
TD=$(mktemp -d "$WORK/XXXXXX"); src="$TD/safe.txt"; dst="$TD/recv"
echo "traversal test" >"$src"
if launch_sender "$src" "$TD/s.out" --name "../../evil.txt"; then
  Q "$WISP" recv "$CODE" --dir "$dst" || true
  # sanitize() strips path components; evil.txt must land inside $dst only
  if [ -f "$dst/evil.txt" ] && [ ! -f "$TD/evil.txt" ] && [ ! -f "$REPO_ROOT/evil.txt" ]; then
    ok "path-traversal display name → 'evil.txt' confined to dst" $((SECONDS - t))
  else
    fail "path-traversal name: file found outside dst!"
  fi
fi
stop_sender

# 6 — SIGINT while sender waits for receiver → exit 130
t=$SECONDS
TD=$(mktemp -d "$WORK/XXXXXX"); src="$TD/file.txt"
echo "sigint test" >"$src"
if launch_sender "$src" "$TD/s.out"; then
  kill -INT "$SPID" 2>/dev/null
  wait "$SPID" 2>/dev/null; ec=$?; SPID=
  if (( ec == 130 )); then
    ok "SIGINT sender (waiting) → exit 130" $((SECONDS - t))
  else
    fail "SIGINT sender: expected exit 130, got $ec"
  fi
fi

# 7 — .wisp-part cleaned up after mid-transfer SIGINT
t=$SECONDS
TD=$(mktemp -d "$WORK/XXXXXX"); src="$TD/medium.bin"; dst="$TD/recv"; mkdir -p "$dst"
# 50 MiB — large enough to still be in-flight when we interrupt
dd if=/dev/urandom bs=1024 count=51200 of="$src" 2>/dev/null
if launch_sender "$src" "$TD/s.out"; then
  Q "$WISP" recv "$CODE" --dir "$dst" &
  recv_pid=$!
  # Wait until receiver has started writing (part file appears) — confirms QUIC connected
  for _ in {1..100}; do
    find "$dst" -name '*.wisp-part' 2>/dev/null | grep -q . && break
    sleep 0.1
  done
  kill -INT "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null || true; SPID=
  wait "$recv_pid" 2>/dev/null || true
  parts=$(find "$dst" -name '*.wisp-part' 2>/dev/null | wc -l)
  if (( parts == 0 )); then
    ok ".wisp-part removed after interrupted transfer" $((SECONDS - t))
  else
    fail ".wisp-part leak: $parts file(s) remain in $dst"
    find "$dst" -name '*.wisp-part'
  fi
fi
stop_sender

# ── relay / WAN ──────────────────────────────────────────────────────────────
section "Relay (WAN)"

"$RELAY" "$RELAY_PORT" >/dev/null 2>&1 &
RPID=$!
sleep 0.3

if ! kill -0 "$RPID" 2>/dev/null; then
  skip "relay startup failed (port $RELAY_PORT may be in use)"
  skip "WAN transfer"
  skip "relay HTTP input validation"
else

  # 8 — WAN happy path
  t=$SECONDS
  TD=$(mktemp -d "$WORK/XXXXXX"); src="$TD/wan.txt"; dst="$TD/recv"
  printf 'WAN relay transfer line\n%.0s' {1..100} >"$src"
  if launch_sender "$src" "$TD/s.out" --relay "$RELAY_URL"; then
    if Q "$WISP" recv "$CODE" --relay "$RELAY_URL" --dir "$dst" \
        && cmp -s "$src" "$dst/wan.txt"; then
      ok "WAN relay transfer — byte-exact" $((SECONDS - t))
    else
      fail "WAN relay transfer (failed or content mismatch)"
    fi
  fi
  stop_sender

  # 9 — relay rejects invalid inputs
  t=$SECONDS
  if command -v curl >/dev/null 2>&1; then
    ch31=$(printf 'a%.0s' {1..31})   # too short (31 instead of 32)
    nohex=$(printf 'g%.0s' {1..32})  # non-hex chars
    ch32=$(printf 'a%.0s' {1..32})   # valid
    fp64=$(printf 'f%.0s' {1..64})   # valid fingerprint

    r1=$(curl -s -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:$RELAY_PORT/pub/${ch31}/${fp64}/9000")   # ch too short → 400
    r2=$(curl -s -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:$RELAY_PORT/pub/${nohex}/${fp64}/9000")  # non-hex ch → 400
    r3=$(curl -s -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:$RELAY_PORT/pub/${ch32}/${fp64}/0")      # port=0 → 400

    if [ "$r1" = "400" ] && [ "$r2" = "400" ] && [ "$r3" = "400" ]; then
      ok "relay: short ch / non-hex ch / port=0 → 400" $((SECONDS - t))
    else
      fail "relay validation: expected 400/400/400, got $r1/$r2/$r3"
    fi
  else
    skip "relay HTTP validation (curl not available)"
  fi

  kill "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null || true; RPID=
fi

# ── slow tests (opt-in) ──────────────────────────────────────────────────────
section "Slow tests"

if [ $SLOW -eq 1 ]; then
  # 10 — wrong code → mDNS times out (~20s), exits non-zero, writes nothing
  t=$SECONDS
  TD=$(mktemp -d "$WORK/XXXXXX"); dst="$TD/recv"; mkdir -p "$dst"
  printf "  (waiting up to 20s for mDNS discovery timeout…)\n"
  Q "$WISP" recv "zz-does-not-exist-smoke" --dir "$dst"; rc=$?
  received=$(find "$dst" -maxdepth 1 -type f 2>/dev/null | wc -l)
  if (( rc != 0 )) && (( received == 0 )); then
    ok "wrong code → non-zero exit, nothing written" $((SECONDS - t))
  else
    fail "wrong code: expected failure (exit=$rc, files=$received)"
  fi
else
  skip "wrong code / 20s mDNS timeout  →  re-run with --slow to include"
fi

# ── summary ──────────────────────────────────────────────────────────────────
total=$(( PASS + FAIL + SKIP ))
printf "\n${CLR_B}Results:${CLR_N}  ${CLR_G}%d passed${CLR_N}  ·  ${CLR_R}%d failed${CLR_N}  ·  ${CLR_Y}%d skipped${CLR_N}  (of %d)\n\n" \
  "$PASS" "$FAIL" "$SKIP" "$total"
[ $FAIL -eq 0 ]
