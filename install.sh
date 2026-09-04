#!/usr/bin/env bash
set -e

# Basic install script for starforge
REPO="StarsForges/StarForge"

# Determine OS and Arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux|darwin) ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

TAR_FILE="starforge-${OS}-${ARCH}.tar.gz"

echo "Fetching latest release for starforge..."
API_URL="https://api.github.com/repos/$REPO/releases/latest"
if command -v curl >/dev/null 2>&1; then
    TAG=$(curl -s "$API_URL" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
else
    echo "curl is required to download starforge"
    exit 1
fi

if [ -z "$TAG" ]; then
    echo "Failed to fetch latest release version"
    exit 1
fi

DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG/$TAR_FILE"
CHECKSUM_URL="https://github.com/$REPO/releases/download/$TAG/checksums.txt"

echo "Downloading $DOWNLOAD_URL..."
curl -sL "$DOWNLOAD_URL" -o "$TAR_FILE" || { echo "Download failed"; exit 1; }

echo "Downloading $CHECKSUM_URL..."
curl -sL "$CHECKSUM_URL" -o checksums.txt || { echo "Checksum download failed"; exit 1; }

echo "Verifying checksum..."
if command -v sha256sum >/dev/null 2>&1; then
    grep "$TAR_FILE" checksums.txt | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
    grep "$TAR_FILE" checksums.txt | shasum -a 256 -c -
else
    echo "Warning: No sha256 checksum tool found. Skipping verification."
fi

echo "Extracting..."
tar -xzf "$TAR_FILE"

INSTALL_DIR="/usr/local/bin"
echo "Installing to $INSTALL_DIR (might require sudo)..."
if [ -w "$INSTALL_DIR" ]; then
    mv -f starforge "$INSTALL_DIR/"
else
    sudo mv -f starforge "$INSTALL_DIR/"
fi
chmod +x "$INSTALL_DIR/starforge"

rm -f "$TAR_FILE" checksums.txt
echo "starforge $TAG installed successfully! Run 'starforge --version' to verify."
