#!/bin/bash

# Simple WireGuard Installer
# Downloads and runs the WireGuard Setup Manager

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://raw.githubusercontent.com/Aaron-EUGameHost/wireguard-install-script/main/wireguard-install.sh"
SCRIPT_NAME="wireguard-install.sh"
TEMP_DIR="/tmp/wg-installer-$$"

# Print colored messages
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Error handling
handle_error() {
    print_message "$RED" "❌ Installation failed!"
    cleanup
    exit 1
}

# Cleanup function
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
}

# Set up error handling
trap handle_error ERR
trap cleanup EXIT

# Welcome message
echo
print_message "$BLUE" "🚀 WireGuard Setup Manager - Simple Installer"
print_message "$BLUE" "=============================================="
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_message "$RED" "❌ This installer must be run as root"
    print_message "$YELLOW" "Please run: sudo $0"
    exit 1
fi

# Check for required tools
print_message "$YELLOW" "🔍 Checking system requirements..."

required_tools=("curl" "chmod")
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        print_message "$RED" "❌ Required tool '$tool' not found"
        print_message "$YELLOW" "Please install $tool and try again"
        exit 1
    fi
done

print_message "$GREEN" "✅ System requirements satisfied"

# Create temporary directory
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Download the main script
print_message "$YELLOW" "📥 Downloading WireGuard Setup Manager..."
if curl -fsSL -o "$SCRIPT_NAME" "$REPO_URL"; then
    print_message "$GREEN" "✅ Download completed successfully"
else
    print_message "$RED" "❌ Failed to download script from: $REPO_URL"
    print_message "$YELLOW" "Please check:"
    print_message "$YELLOW" "  • Internet connection"
    print_message "$YELLOW" "  • Repository is public and accessible"
    print_message "$YELLOW" "  • File exists at the specified location"
    exit 1
fi

# Verify download
if [[ ! -f "$SCRIPT_NAME" ]] || [[ ! -s "$SCRIPT_NAME" ]]; then
    print_message "$RED" "❌ Downloaded file is empty or missing"
    exit 1
fi

# Check if it's a valid shell script
if ! head -1 "$SCRIPT_NAME" | grep -q "^#!/bin/bash"; then
    print_message "$RED" "❌ Downloaded file doesn't appear to be a valid bash script"
    print_message "$YELLOW" "First line: $(head -1 "$SCRIPT_NAME")"
    exit 1
fi

# Make executable
print_message "$YELLOW" "🔧 Making script executable..."
chmod +x "$SCRIPT_NAME"

# Show script info
script_size=$(wc -l < "$SCRIPT_NAME")
print_message "$GREEN" "✅ Script prepared ($script_size lines)"

echo
print_message "$BLUE" "🎯 Starting WireGuard Setup Manager..."
print_message "$BLUE" "====================================="
echo

# Execute the main script
exec "./$SCRIPT_NAME" "$@"
