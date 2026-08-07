#!/usr/bin/env bash
# uninstall.sh — remove the domainblock systemd service/timer.
#
# By default this stops and removes the timer + service unit and the service
# user. It does NOT delete this install directory or your config/patterns, and
# it does NOT touch the router (remove the firewall rules yourself if you want —
# see README). Existing banned entries expire on their own timeout.
#
# Usage:  sudo ./uninstall.sh [--keep-user]
#   --keep-user   leave the 'domainblock' service account in place

set -euo pipefail

SERVICE_USER="domainblock"
SERVICE_FILE="/etc/systemd/system/domainblock.service"
TIMER_FILE="/etc/systemd/system/domainblock.timer"
KEEP_USER=0

[[ "${1:-}" == "--keep-user" ]] && KEEP_USER=1

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo ./uninstall.sh)." >&2
  exit 1
fi

echo ">> Stopping and disabling timer/service"
systemctl disable --now domainblock.timer 2>/dev/null || true
systemctl stop domainblock.service 2>/dev/null || true

echo ">> Removing unit files"
rm -f "$TIMER_FILE" "$SERVICE_FILE"

echo ">> Reloading systemd"
systemctl daemon-reload
systemctl reset-failed domainblock.service 2>/dev/null || true

if [[ $KEEP_USER -eq 0 ]]; then
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    echo ">> Removing service user '$SERVICE_USER'"
    userdel "$SERVICE_USER" 2>/dev/null || true
  fi
else
  echo ">> Keeping service user '$SERVICE_USER' (--keep-user)"
fi

echo ""
echo "Done. Service and timer removed."
echo "This directory and your config/patterns are untouched."
echo ""
echo "Reminder — the router still has its firewall rules and any active bans."
echo "To fully clean the router side:"
echo "  /ip firewall filter remove [find where src-address-list=domainblock-banned]"
echo "  /ip firewall filter remove [find where address-list=domainblock-check]"
echo "  /ip firewall address-list remove [find where list=domainblock-banned]"
echo "  /ip firewall address-list remove [find where list=domainblock-check]"
