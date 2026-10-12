#!/usr/bin/env bash
# Install ddnspy as a systemd service (Debian, Ubuntu, Raspberry Pi OS, ...).
# Usage: sudo ./install.sh
set -euo pipefail

SERVICE_NAME=ddnspy
SERVICE_USER=ddnspy
INSTALL_BIN="${DDNSPY_BIN:-/usr/local/bin/ddnspy}"
CONF_DIR="${DDNSPY_CONF_DIR:-/etc/ddnspy}"
UNIT_FILE=/etc/systemd/system/ddnspy.service
LOG_DIR=/var/log/ddnspy

src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "error: please run as root (sudo ./install.sh)"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found"; exit 1; }
systemctl --version >/dev/null 2>&1 || { echo "error: systemd not found (systemctl missing)"; exit 1; }
[ -f "$src_dir/ddnspy.py" ] || { echo "error: ddnspy.py not found next to install.sh"; exit 1; }

# 1) dedicated system user (no login shell, owns nothing but the log dir)
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home \
            --home-dir /var/lib/ddnspy --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "created system user: $SERVICE_USER"
fi

# 2) binary
install -D -m 0755 "$src_dir/ddnspy.py" "$INSTALL_BIN"

# 3) config (never overwrite an existing one)
mkdir -p "$CONF_DIR"
chown root:"$SERVICE_USER" "$CONF_DIR"
chmod 0750 "$CONF_DIR"
if [ -f "$CONF_DIR/config.json" ]; then
    install -m 0640 -o root -g "$SERVICE_USER" "$src_dir/config.json" \
        "$CONF_DIR/config.json.new"
    echo "note: $CONF_DIR/config.json already exists — left untouched;"
    echo "      a fresh template was written to $CONF_DIR/config.json.new (merge manually if needed)"
else
    install -m 0640 -o root -g "$SERVICE_USER" "$src_dir/config.json" \
        "$CONF_DIR/config.json"
    echo "installed config: $CONF_DIR/config.json (contains your API token — keep it private)"
fi

# 4) log dir
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR"

# 5) systemd unit
install -m 0644 "$src_dir/ddnspy.service" "$UNIT_FILE"
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME.service"

echo
systemctl --no-pager -l status "$SERVICE_NAME.service" || true
echo
echo "done. useful commands:"
echo "  systemctl status ddnspy              # service state"
echo "  journalctl -u ddnspy -f              # follow logs"
echo "  sudoedit /etc/ddnspy/config.json     # edit config, then: sudo systemctl restart ddnspy"
