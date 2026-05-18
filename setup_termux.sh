#!/bin/bash
# NIL v4.0 Termux Setup Script
# Run: bash setup_termux.sh

set -e

echo "=== NIL v4.0 Termux Setup ==="
echo ""

# Update packages
echo "[1/4] Updating package lists..."
pkg update -y

# Install compiler, build tools, and available libraries
echo "[2/4] Installing dependencies..."
pkg install -y gcc make cmake git sqlite openssl libssl-dev curl libpcre2

# Build json-c from source (not available as a Termux package)
echo "[3/4] Building json-c from source..."
if [ -f "$PREFIX/include/json-c/json.h" ]; then
    echo "  json-c already installed, skipping."
else
    BUILD_DIR="$HOME/.nil-build/json-c"
    mkdir -p "$HOME/.nil-build"
    if [ ! -d "$BUILD_DIR" ]; then
        git clone --depth=1 https://github.com/json-c/json-c.git "$BUILD_DIR"
    fi
    cd "$BUILD_DIR"
    mkdir -p build && cd build
    cmake .. -DCMAKE_INSTALL_PREFIX="$PREFIX"
    make -j4
    make install
    cd "$HOME"
    echo "  json-c installed."
fi

# Verify
echo ""
echo "[4/4] Verifying installations..."
echo -n "  gcc:          "; gcc --version 2>/dev/null | head -1 || echo "NOT FOUND"
echo -n "  make:         "; make --version 2>/dev/null | head -1 || echo "NOT FOUND"
echo -n "  cmake:        "; cmake --version 2>/dev/null | head -1 || echo "NOT FOUND"
echo -n "  sqlite3:      "; sqlite3 --version 2>/dev/null || echo "NOT FOUND"
echo -n "  curl:         "; curl --version 2>/dev/null | head -1 || echo "NOT FOUND"
echo -n "  pcre2:        "
if [ -f "$PREFIX/include/pcre2.h" ]; then echo "Found"; else echo "NOT FOUND"; fi
echo -n "  json-c:       "
if [ -f "$PREFIX/include/json-c/json.h" ]; then echo "Found"; else echo "NOT FOUND"; fi
echo -n "  openssl:      "
if [ -f "$PREFIX/include/openssl/sha.h" ]; then echo "Found"; else echo "NOT FOUND"; fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Compile NIL with:"
echo "  make"
echo ""
echo "Or manually:"
echo "  gcc -O2 -Wall -pthread -o nil nil.c -lsqlite3 -lssl -lcrypto -lm -lcurl -ljson-c -lpcre2-8"
echo ""
echo "Then initialize:"
echo "  ./nil init"
