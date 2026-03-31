#!/bin/bash
# Install the Credential Gate launchd agent.

set -euo pipefail

PLIST_NAME="com.pete.credential-gate.plist"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_PLIST="${SRC_DIR}/${PLIST_NAME}"
DEST_DIR="${HOME}/Library/LaunchAgents"
DEST_PLIST="${DEST_DIR}/${PLIST_NAME}"
LOG_DIR="${SRC_DIR}/logs"

echo "Credential Gate — Install Service"
echo "================================="

# Create logs directory
mkdir -p "${LOG_DIR}"
echo "Logs directory: ${LOG_DIR}"

# Create LaunchAgents directory if needed
mkdir -p "${DEST_DIR}"

# Unload if already loaded
if launchctl list | grep -q "com.pete.credential-gate"; then
    echo "Unloading existing service..."
    launchctl unload "${DEST_PLIST}" 2>/dev/null || true
fi

# Copy plist
cp "${SRC_PLIST}" "${DEST_PLIST}"
echo "Installed plist to: ${DEST_PLIST}"

# Load the agent
launchctl load "${DEST_PLIST}"
echo "Service loaded."

# Verify
sleep 1
if launchctl list | grep -q "com.pete.credential-gate"; then
    echo "Service is running."
else
    echo "WARNING: Service may not be running. Check:"
    echo "  launchctl list | grep credential-gate"
    echo "  tail -f ${LOG_DIR}/credential-gate.log"
fi

echo ""
echo "Useful commands:"
echo "  View logs:       tail -f ${LOG_DIR}/credential-gate.log"
echo "  Check status:    curl http://127.0.0.1:8200/health"
echo "  Restart:         ${SRC_DIR}/restart-service.sh"
echo "  Uninstall:       ${SRC_DIR}/uninstall-service.sh"
