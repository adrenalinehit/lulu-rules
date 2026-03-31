#!/usr/bin/env bash
# install.sh — Install lulu-rules and register the hourly LaunchDaemon.
# Must be run as root: sudo bash install.sh
set -euo pipefail

INSTALL_DIR=/usr/local/lib/lulu-rules
STATE_DIR=/var/db/lulu-rules
LOG_DIR=/var/log/lulu-rules
DAEMON_DEST=/Library/LaunchDaemons/com.lulu-rules.plist
DAEMON_LABEL=com.lulu-rules

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "Error: install.sh must be run as root."
    echo "  sudo bash install.sh"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found. Install Xcode Command Line Tools:"
    echo "  xcode-select --install"
    exit 1
fi

if ! command -v lulu-cli &>/dev/null; then
    echo "Error: lulu-cli not found."
    echo "Install via Homebrew:"
    echo "  brew install woop/tap/lulu-cli"
    echo "Or from source:"
    echo "  https://github.com/woop/lulu-cli"
    exit 1
fi

if ! command -v swiftc &>/dev/null; then
    echo "Error: swiftc not found. Install Xcode Command Line Tools:"
    echo "  xcode-select --install"
    exit 1
fi

echo "lulu-cli found at: $(command -v lulu-cli)"
echo "python3  found at: $(command -v python3)"
echo "swiftc   found at: $(command -v swiftc)"

# ---------------------------------------------------------------------------
# Create directories
# ---------------------------------------------------------------------------

echo "Creating directories..."
mkdir -p "$INSTALL_DIR" "$STATE_DIR" "$LOG_DIR"
chmod 700 "$STATE_DIR"   # state file contains no secrets but limit access
chmod 755 "$INSTALL_DIR" "$LOG_DIR"

# ---------------------------------------------------------------------------
# Copy files
# ---------------------------------------------------------------------------

echo "Installing package to $INSTALL_DIR..."
cp -r "$SCRIPT_DIR/lulu_rules/" "$INSTALL_DIR/lulu_rules/"
cp -r "$SCRIPT_DIR/config/" "$INSTALL_DIR/config/"

chown -R root:wheel "$INSTALL_DIR"
chmod -R 644 "$INSTALL_DIR/lulu_rules/"*.py
chmod -R 644 "$INSTALL_DIR/config/"*.json

# ---------------------------------------------------------------------------
# Compile the Swift plist helper
# ---------------------------------------------------------------------------

echo "Compiling Swift plist helper..."
swiftc "$SCRIPT_DIR/scripts/plist_helper.swift" \
    -O \
    -o "$INSTALL_DIR/lulu-rules-helper" 2>&1
chown root:wheel "$INSTALL_DIR/lulu-rules-helper"
chmod 755 "$INSTALL_DIR/lulu-rules-helper"
echo "Swift helper compiled at $INSTALL_DIR/lulu-rules-helper"

# ---------------------------------------------------------------------------
# Install LaunchDaemon
# ---------------------------------------------------------------------------

echo "Installing LaunchDaemon to $DAEMON_DEST..."
cp "$SCRIPT_DIR/launchd/com.lulu-rules.plist" "$DAEMON_DEST"
chown root:wheel "$DAEMON_DEST"
chmod 644 "$DAEMON_DEST"

# Unload any previously running instance
if launchctl print "system/$DAEMON_LABEL" &>/dev/null 2>&1; then
    echo "Stopping existing daemon..."
    launchctl bootout "system/$DAEMON_LABEL" 2>/dev/null || true
    sleep 1
fi

echo "Loading LaunchDaemon..."
launchctl bootstrap system "$DAEMON_DEST"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "lulu-rules installed successfully."
echo ""
echo "The first feed fetch is running now. Monitor progress:"
echo "  tail -f $LOG_DIR/updater.log"
echo ""
echo "To run a manual update at any time:"
echo "  sudo bash $SCRIPT_DIR/update.sh"
echo ""
echo "To perform a full rebuild (remove and re-add all rules):"
echo "  sudo bash $SCRIPT_DIR/update.sh --force-rebuild"
echo ""
echo "To uninstall:"
echo "  sudo bash $SCRIPT_DIR/uninstall.sh"
