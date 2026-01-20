#!/bin/bash
# ANVIL Setup Script - Build and install ANVIL

set -e

echo "========================================="
echo "   ANVIL Setup Script"
echo "========================================="
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust is not installed."
    echo "📦 Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "✅ Rust installed successfully!"
else
    echo "✅ Rust is already installed ($(rustc --version))"
fi

# Ensure cargo is in PATH
if ! command -v cargo &> /dev/null; then
    echo "📌 Adding cargo to PATH..."
    source "$HOME/.cargo/env"
fi

echo ""
echo "🔨 Building ANVIL in release mode..."
cargo build --release

echo ""
echo "📦 Installing ANVIL..."
cargo install --path .

echo ""
echo "========================================="
echo "   ✅ Setup Complete!"
echo "========================================="
echo ""
echo "ANVIL has been installed to: ~/.cargo/bin/anvil"
echo ""
echo "To use ANVIL globally, run:"
echo "  source \$HOME/.cargo/env"
echo ""
echo "Or add to your ~/.bashrc:"
echo "  echo '. \"\$HOME/.cargo/env\"' >> ~/.bashrc"
echo ""
echo "Test the installation:"
echo "  anvil --version"
echo "  anvil --help"
echo ""
