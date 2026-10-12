#!/usr/bin/env bash
# Remove the ddnspy systemd service.
# The config in /etc/ddnspy is kept (it contains your API token).
set -euo pipefail

SERVICE_NAME=ddnspy
SERVICE_USER=ddnspy

[ "$(id -u)" -eq 0 ] || { echo "error: please run as root"; exit 1; }

systemctl disable --now "$SERVICE_NAME.service" 2>/dev/null || true
rm -f /etc/systemd/system/ddnspy.service /usr/local/bin/ddnspy
rm -rf /var/log/ddnspy
userdel "$SERVICE_USER" 2>/dev/null || true
groupdel "$SERVICE_USER" 2>/dev/null || true
systemctl daemon-reload

echo "ddnspy service removed."
echo "kept: /etc/ddnspy/config.json (contains your API token — remove manually if desired)"
