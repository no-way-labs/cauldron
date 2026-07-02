#!/bin/bash

set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

echo "Building all apps..."
# ReleaseSafe: optimized, but keeps runtime safety checks (bounds, overflow,
# @intCast/@enumFromInt) so malformed network input panics instead of becoming
# undefined behavior. Matches what CI ships.
zig build -Doptimize=ReleaseSafe

echo "Creating install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "Installing binaries to $INSTALL_DIR..."
for binary in zig-out/bin/*; do
    if [ -f "$binary" ]; then
        filename=$(basename "$binary")
        cp "$binary" "$INSTALL_DIR/$filename"
        chmod +x "$INSTALL_DIR/$filename"
        echo "  ✓ Installed $filename"
    fi
done

echo ""
echo "Installation complete!"
echo ""
echo "Make sure $INSTALL_DIR is in your PATH."
echo "Add this to your ~/.bashrc or ~/.zshrc if not already there:"
echo ""
echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
