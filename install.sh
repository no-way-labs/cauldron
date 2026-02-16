#!/bin/bash

set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

echo "Building all apps..."
zig build

echo "Creating install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "Installing binaries to $INSTALL_DIR..."
for binary in zig-out/bin/*; do
    if [ -f "$binary" ]; then
        filename=$(basename "$binary")
        cp "$binary" "$INSTALL_DIR/cauldron-$filename"
        chmod +x "$INSTALL_DIR/cauldron-$filename"
        echo "  ✓ Installed cauldron-$filename"
    fi
done

echo ""
echo "Installation complete!"
echo ""
echo "Make sure $INSTALL_DIR is in your PATH."
echo "Add this to your ~/.bashrc or ~/.zshrc if not already there:"
echo ""
echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
echo ""
echo "Then reload your shell or run: source ~/.bashrc (or ~/.zshrc)"
echo ""
echo "You can now run: cauldron-hello-world -- YourName"
