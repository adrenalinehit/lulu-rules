#!/usr/bin/env bash
# uninstall.sh — Remove lulu-rules, its LaunchDaemon, and all managed LuLu rules.
# Must be run as root: sudo bash uninstall.sh
set -euo pipefail

INSTALL_DIR=/usr/local/lib/lulu-rules
STATE_DIR=/var/db/lulu-rules
LOG_DIR=/var/log/lulu-rules
DAEMON_DEST=/Library/LaunchDaemons/com.lulu-rules.plist
DAEMON_LABEL=com.lulu-rules

if [[ $EUID -ne 0 ]]; then
    echo "Error: uninstall.sh must be run as root."
    echo "  sudo bash uninstall.sh"
    exit 1
fi

# Stop and remove daemon
if launchctl print "system/$DAEMON_LABEL" &>/dev/null 2>&1; then
    echo "Stopping LaunchDaemon..."
    launchctl bootout "system/$DAEMON_LABEL" 2>/dev/null || true
fi
rm -f "$DAEMON_DEST"

# Remove managed LuLu rules
if command -v lulu-cli &>/dev/null; then
    echo "Removing managed LuLu block rules..."
    lulu-cli delete --key com.lulu-rules.c2-feeds 2>/dev/null || true
    lulu-cli reload 2>/dev/null || true
else
    echo "Warning: lulu-cli not found — managed rules may remain in LuLu."
fi

# Remove installed files
echo "Removing installed files..."
rm -rf "$INSTALL_DIR"
rm -rf "$STATE_DIR"

echo "Log files retained at $LOG_DIR — remove manually if desired:"
echo "  sudo rm -rf $LOG_DIR"
echo ""
echo "lulu-rules uninstalled."
