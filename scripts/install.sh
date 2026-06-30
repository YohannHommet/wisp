#!/usr/bin/env bash
set -e

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM=linux;;
    Darwin*)    PLATFORM=macos;;
    *)          echo "Unsupported OS: ${OS}"; exit 1;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64*)    ARCH_SUFFIX=amd64;;
    arm64*|aarch64*)  ARCH_SUFFIX=arm64;;
    *)          echo "Unsupported architecture: ${ARCH}"; exit 1;;
esac

# Resolve Asset Name
if [ "${PLATFORM}" = "macos" ]; then
    # We distribute a universal binary for macOS
    ASSET_NAME="wisp-macos-universal"
else
    ASSET_NAME="wisp-linux-${ARCH_SUFFIX}"
fi

URL="https://github.com/YohannHommet/wisp/releases/latest/download/${ASSET_NAME}"
INSTALL_DIR="/usr/local/bin"
DEST="${INSTALL_DIR}/wisp"

echo "Downloading Wisp from ${URL}..."

# Download binary
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o wisp_temp "${URL}"
elif command -v wget >/dev/null 2>&1; then
    wget -qO wisp_temp "${URL}"
else
    echo "Error: curl or wget is required to download Wisp."
    exit 1
fi

chmod +x wisp_temp

echo "Installing to ${DEST}..."
if [ -w "${INSTALL_DIR}" ]; then
    mv wisp_temp "${DEST}"
else
    echo "Requires sudo privileges to write to ${INSTALL_DIR}"
    sudo mv wisp_temp "${DEST}"
fi

echo "Successfully installed Wisp CLI!"
wisp --version
