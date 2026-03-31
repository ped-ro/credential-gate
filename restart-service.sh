#!/bin/bash
# Restart the Credential Gate launchd agent.

set -euo pipefail

PLIST_NAME="com.pete.credential-gate.plist"
DEST_PLIST="${HOME}/Library/LaunchAgents/${PLIST_NAME}"

echo "Credential Gate — Restart Service"
echo "================================="

if [ ! -f "${DEST_PLIST}" ]; then
    echo "Service plist not found at ${DEST_PLIST}"
    echo "Run install-service.sh first."
    exit 1
fi

echo "Unloading..."
launchctl unload "${DEST_PLIST}" 2>/dev/null || true

echo "Loading..."
launchctl load "${DEST_PLIST}"

sleep 1
if launchctl list | grep -q "com.pete.credential-gate"; then
    echo "Service restarted."
else
    echo "WARNING: Service may not be running. Check logs."
fi
