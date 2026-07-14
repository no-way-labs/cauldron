#!/usr/bin/env bash

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-0.0.0-dev}"
APPS=(mitt seance familiar omen covenant)

if ! command -v go >/dev/null 2>&1; then
    echo "Go 1.26 or newer is required." >&2
    exit 1
fi

build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT

echo "Building all apps with Go..."
for app in "${APPS[@]}"; do
    CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=$VERSION" \
        -o "$build_dir/$app" "./cmd/$app"
done

echo "Creating install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "Installing binaries to $INSTALL_DIR..."
for app in "${APPS[@]}"; do
    install -m 0755 "$build_dir/$app" "$INSTALL_DIR/$app"
    echo "  ✓ Installed $app"
done

echo
echo "Installation complete!"
echo
echo "Make sure $INSTALL_DIR is in your PATH."
echo "Add this to your ~/.bashrc or ~/.zshrc if needed:"
echo
echo '    export PATH="$HOME/.local/bin:$PATH"'
