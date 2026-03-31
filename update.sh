#!/usr/bin/env bash
# update.sh — Run a manual lulu-rules update.
# Accepts all updater flags: --dry-run, --force-rebuild, --config PATH
# Must be run as root: sudo bash update.sh [flags]
set -euo pipefail

INSTALL_DIR=/usr/local/lib/lulu-rules
CONFIG="$INSTALL_DIR/config/feeds.json"

if [[ $EUID -ne 0 ]]; then
    echo "Error: update.sh must be run as root."
    echo "  sudo bash update.sh"
    exit 1
fi

exec /usr/bin/python3 -m lulu_rules.updater --config "$CONFIG" "$@"
