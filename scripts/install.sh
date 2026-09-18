#!/usr/bin/env bash
# Install a published CLI release. Verify SHA-256 before replacing a user binary.
set -euo pipefail
repo='https://github.com/YohannHommet/wisp'
case "$(uname -s)" in
  Linux) platform=linux ;;
  Darwin) platform=macos ;;
  *) echo 'Use install.ps1 on Windows.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo 'Unsupported architecture.' >&2; exit 1 ;;
esac
asset="wisp-${platform}-${arch}"
if [[ "$platform" == macos ]]; then asset=wisp-macos-universal; fi
command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
version="${WISP_VERSION:-}"
if [[ -z "$version" ]]; then
  resolved=$(curl --proto '=https' --tlsv1.2 -fsSL -o /dev/null -w '%{url_effective}' "$repo/releases/latest")
  version="${resolved##*/}"
fi
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "No published release tag found at $repo/releases/latest (got '$version')." >&2
  echo "Specify an explicit tag with WISP_VERSION=vX.Y.Z, or install from source with Cargo:" >&2
  echo "  cargo install --locked --path crates/wisp-cli" >&2
  exit 1
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/wisp.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
base="$repo/releases/download/$version"
curl --proto '=https' --tlsv1.2 -fSL "$base/$asset" -o "$work/$asset"
curl --proto '=https' --tlsv1.2 -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS"
expected=$(awk -v asset="$asset" '$2 == asset {print $1}' "$work/SHA256SUMS")
if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then echo 'Missing or ambiguous release checksum.' >&2; exit 1; fi
if command -v sha256sum >/dev/null; then actual=$(sha256sum "$work/$asset");
else actual=$(shasum -a 256 "$work/$asset"); fi
actual="${actual%% *}"
if [[ "$actual" != "$expected" ]]; then echo 'Checksum mismatch; nothing installed.' >&2; exit 1; fi
install_dir="${WISP_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p -- "$install_dir"
if [[ -d "$install_dir/wisp" ]]; then
  echo "Cannot replace a directory at $install_dir/wisp; nothing installed." >&2
  exit 1
fi
# Stage in the destination filesystem so replacement is atomic.
staged=$(mktemp "$install_dir/.wisp-install.XXXXXX")
trap 'rm -rf -- "$work"; rm -f -- "$staged"' EXIT
install -m 755 "$work/$asset" "$staged"
mv -f -- "$staged" "$install_dir/wisp"
echo "Installed $version at $install_dir/wisp"
case ":$PATH:" in *":$install_dir:"*) ;; *) echo "Add $install_dir to PATH to run wisp from any directory." ;; esac
