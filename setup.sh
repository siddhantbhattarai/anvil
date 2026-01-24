#!/bin/bash

# ANVIL Setup Script for Linux/macOS
# This script installs ANVIL and sets up the environment

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    ANVIL Setup Script                          ║"
echo "║        Enterprise-grade Security Testing Framework             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if Rust is installed
check_rust() {
    if command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version | cut -d' ' -f2)
        print_status "Rust is installed (version $RUST_VERSION)"
        return 0
    else
        return 1
    fi
}

# Install Rust
install_rust() {
    print_status "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    print_status "Rust installed successfully"
}

# Build ANVIL
build_anvil() {
    print_status "Building ANVIL in release mode..."
    cargo build --release
    print_status "Build completed"
}

# Install ANVIL
install_anvil() {
    print_status "Installing ANVIL..."
    cargo install --path .
    print_status "ANVIL installed successfully"
}

# Add to PATH
setup_path() {
    CARGO_BIN="$HOME/.cargo/bin"
    
    # Check which shell config file to use
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    else
        SHELL_RC="$HOME/.profile"
    fi
    
    # Check if already in PATH
    if [[ ":$PATH:" != *":$CARGO_BIN:"* ]]; then
        echo "" >> "$SHELL_RC"
        echo "# ANVIL - Added by setup script" >> "$SHELL_RC"
        echo "export PATH=\"\$PATH:$CARGO_BIN\"" >> "$SHELL_RC"
        print_status "Added $CARGO_BIN to PATH in $SHELL_RC"
        print_warning "Run 'source $SHELL_RC' or restart your terminal"
    else
        print_status "Cargo bin already in PATH"
    fi
}

# Verify installation
verify_installation() {
    if command -v anvil &> /dev/null; then
        ANVIL_VERSION=$(anvil --version 2>&1 | head -1)
        print_status "ANVIL installed successfully!"
        echo ""
        echo "  Version: $ANVIL_VERSION"
        echo ""
        echo "  Quick start:"
        echo "    anvil --help"
        echo "    anvil -t 'http://target.com/page?id=1' -p id --sqli --dbs"
        echo ""
    else
        print_warning "ANVIL installed but not in current PATH"
        print_warning "Run: source ~/.bashrc (or ~/.zshrc)"
    fi
}

# Main installation flow
main() {
    echo "Starting ANVIL installation..."
    echo ""
    
    # Check/Install Rust
    if ! check_rust; then
        print_warning "Rust not found"
        read -p "Install Rust? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_rust
        else
            print_error "Rust is required to build ANVIL"
            exit 1
        fi
    fi
    
    # Build and install
    build_anvil
    install_anvil
    setup_path
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    verify_installation
    echo "════════════════════════════════════════════════════════════════"
}

# Run main
main
