#!/bin/bash
# Uninstall the Credential Gate launchd agent.

set -euo pipefail

PLIST_NAME="com.pete.credential-gate.plist"
DEST_PLIST="${HOME}/Library/LaunchAgents/${PLIST_NAME}"

echo "Credential Gate — Uninstall Service"
echo "===================================="

if [ -f "${DEST_PLIST}" ]; then
    echo "Unloading service..."
    launchctl unload "${DEST_PLIST}" 2>/dev/null || true
    rm "${DEST_PLIST}"
    echo "Service unloaded and plist removed."
else
    echo "Service plist not found at ${DEST_PLIST} — nothing to uninstall."
fi
