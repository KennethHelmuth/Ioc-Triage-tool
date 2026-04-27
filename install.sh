#!/bin/bash
# Detects OS and architecture
# Downloads the correct binary from latest GitHub release
# Places it in /usr/local/bin/ioc-triage
# Makes it executable
# Prints success message with usage instructions

set -e

REPO="KennethHelmuth/Ioc-Triage-tool"
BINARY="ioc-triage"
DEST_DIR="/usr/local/bin"

echo "Fetching latest release information for $REPO..."

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM="unknown-linux-gnu";;
    Darwin*)    PLATFORM="apple-darwin";;
    *)          echo "Unsupported OS: ${OS}"; exit 1;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64*)    TARGET_ARCH="x86_64";;
    arm64*|aarch64*)
        if [ "$OS" = "Darwin" ]; then
            TARGET_ARCH="aarch64"
        else
            echo "Unsupported architecture for Linux: ${ARCH}"; exit 1
        fi
        ;;
    *)          echo "Unsupported architecture: ${ARCH}"; exit 1;;
esac

TARGET="${TARGET_ARCH}-${PLATFORM}"

# Get the latest release tag
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep -Po '"tag_name": "\K.*?(?=")')

if [ -z "$LATEST_TAG" ]; then
    echo "Error: Failed to fetch latest release version."
    exit 1
fi

VERSION="${LATEST_TAG#v}"
FILENAME="${BINARY}-${VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$FILENAME"

echo "Downloading $BINARY v$VERSION for $TARGET..."

TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

if command -v curl >/dev/null 2>&1; then
    curl -fsSLO "$DOWNLOAD_URL"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$DOWNLOAD_URL"
else
    echo "Error: curl or wget is required to download the binary."
    exit 1
fi

if [ ! -f "$FILENAME" ]; then
    echo "Error: Failed to download $FILENAME from $DOWNLOAD_URL"
    exit 1
fi

echo "Extracting archive..."
tar -xzf "$FILENAME"

if [ ! -f "$BINARY" ]; then
    echo "Error: Extraction failed, $BINARY not found in archive."
    exit 1
fi

echo "Installing to $DEST_DIR (requires sudo)..."
if ! sudo mv "$BINARY" "$DEST_DIR/$BINARY"; then
    echo "Error: Failed to move binary to $DEST_DIR. Please check your permissions."
    exit 1
fi

sudo chmod +x "$DEST_DIR/$BINARY"

echo "Cleaning up..."
rm -rf "$TMP_DIR"

echo "✅ Successfully installed $BINARY v$VERSION to $DEST_DIR/$BINARY!"
echo "You can now run it by typing: $BINARY"
