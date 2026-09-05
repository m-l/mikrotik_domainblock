#!/usr/bin/env bash
# install.sh — set up domainblock as a background systemd service.
#
# Everything stays self-contained in the install directory (this folder).
# Config and patterns live here, next to the script. The service runs the
# script on a timer as an unprivileged user.
#
# Usage:  sudo ./install.sh [interval_seconds]
#   interval_seconds  how often to run the check (default: 30)
#
# Re-running is safe: it updates the units and restarts the timer.
set -euo pipefail
# --- resolve paths ----------------------------------------------------------
INSTALL_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
INTERVAL="${1:-30}"
SERVICE_USER="domainblock"
RUBY_BIN="$(command -v ruby || true)"
SERVICE_FILE="/etc/systemd/system/domainblock.service"
TIMER_FILE="/etc/systemd/system/domainblock.timer"
# --- checks -----------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo ./install.sh)." >&2
  exit 1
fi
if [[ -z "$RUBY_BIN" ]]; then
  echo "Ruby not found in PATH. Install Ruby first." >&2
  exit 1
fi
if [[ ! -f "$INSTALL_DIR/domainblock.rb" ]]; then
  echo "domainblock.rb not found in $INSTALL_DIR — run this from the install folder." >&2
  exit 1
fi
if [[ ! -f "$INSTALL_DIR/config.yml" ]]; then
  echo "config.yml not found in $INSTALL_DIR — copy/edit it before installing." >&2
  exit 1
fi
echo ">> Install dir : $INSTALL_DIR"
echo ">> Ruby        : $RUBY_BIN"
echo ">> Interval    : ${INTERVAL}s"
echo ">> Service user: $SERVICE_USER"
# --- service account --------------------------------------------------------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  echo ">> Creating service user '$SERVICE_USER'"
  useradd -r -s /usr/sbin/nologin "$SERVICE_USER"
else
  echo ">> Service user '$SERVICE_USER' already exists"
fi
# --- permissions ------------------------------------------------------------
# config.yml holds the router password -> restrict it.
chown root:"$SERVICE_USER" "$INSTALL_DIR/config.yml"
chmod 640 "$INSTALL_DIR/config.yml"
# script + patterns readable by the service user
chmod 755 "$INSTALL_DIR/domainblock.rb"
[[ -f "$INSTALL_DIR/domainblock-patterns.txt" ]] && chmod 644 "$INSTALL_DIR/domainblock-patterns.txt"
# let the service user read the directory
chmod 755 "$INSTALL_DIR"
# The service writes ban-cache.txt in the install dir (atomic temp+rename, so it
# needs write on the DIRECTORY, not just the file). Give the service user
# ownership of the dir and the cache file so persist/restore can write.
chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
if [[ -f "$INSTALL_DIR/ban-cache.txt" ]]; then
  chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/ban-cache.txt"
fi
# --- systemd service --------------------------------------------------------
echo ">> Writing $SERVICE_FILE"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=domainblock - reverse-DNS pattern blocker (writes to MikroTik)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$RUBY_BIN $INSTALL_DIR/domainblock.rb
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
# PrivateTmp MUST be no: the run counter lives in /tmp and must persist across
# the per-tick oneshot invocations. With PrivateTmp=yes each run gets its own
# ephemeral /tmp, the counter never persists, and the ban cache never comes due.
PrivateTmp=no
# The service writes two files and both paths must be writable, or the writes
# fail silently (rescued in-script) and the ban cache never updates:
#   - $INSTALL_DIR    -> ban-cache.txt
#   - /tmp            -> run counter (ban_cache_counter default)
# Do NOT add ReadOnlyPaths=$INSTALL_DIR here — it contradicts ReadWritePaths
# and re-blocks the cache write.
ReadWritePaths=$INSTALL_DIR /tmp
EOF
# --- systemd timer ----------------------------------------------------------
echo ">> Writing $TIMER_FILE (every ${INTERVAL}s)"
cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run domainblock reverse-DNS check every ${INTERVAL}s
[Timer]
OnBootSec=${INTERVAL}s
OnUnitActiveSec=${INTERVAL}s
AccuracySec=5s
Unit=domainblock.service
[Install]
WantedBy=timers.target
EOF
# --- logrotate: seen.csv, monthly, 6 kept ------------------------------------
# Safe regardless of whether seen_log is enabled in config.yml — logrotate's
# own `missingok` just skips a file that doesn't exist. No coordination with
# the running script needed: domainblock.rb opens seen.csv fresh (File.open
# "a") on every 30s tick rather than holding it open, so logrotate can rename
# it out from under the script at any moment and the next tick just creates a
# new empty file at that path.
LOGROTATE_FILE="/etc/logrotate.d/domainblock"
echo ">> Writing $LOGROTATE_FILE (monthly, 6 kept)"
cat > "$LOGROTATE_FILE" <<EOF
$INSTALL_DIR/seen.csv {
    monthly
    rotate 6
    missingok
    notifempty
    dateext
    dateformat -%Y-%m
    compress
    create 640 $SERVICE_USER $SERVICE_USER
}
EOF
# --- optional monthly coverage-report timer ----------------------------------
# Installed unconditionally (like the other opt-in features), but the script
# itself checks `monthly_report` in config.yml and exits immediately if it's
# not set to true, so this is a no-op until you turn it on there.
REPORT_SERVICE_FILE="/etc/systemd/system/domainblock-report.service"
REPORT_TIMER_FILE="/etc/systemd/system/domainblock-report.timer"
echo ">> Writing $REPORT_SERVICE_FILE / $REPORT_TIMER_FILE (3rd of each month)"
cat > "$REPORT_SERVICE_FILE" <<EOF
[Unit]
Description=domainblock - monthly pattern-coverage report (no-op unless monthly_report: true)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$RUBY_BIN $INSTALL_DIR/domainblock-monthly-report.rb
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR
EOF
cat > "$REPORT_TIMER_FILE" <<EOF
[Unit]
Description=Run the domainblock monthly coverage report
[Timer]
# 3rd of each month, not the 1st — gives logrotate's daily cron a full
# buffer to have already rotated last month's seen.csv by the time this runs.
OnCalendar=*-*-03 04:00:00
AccuracySec=1h
Persistent=true
Unit=domainblock-report.service
[Install]
WantedBy=timers.target
EOF
# --- enable -----------------------------------------------------------------
echo ">> Reloading systemd and enabling timers"
systemctl daemon-reload
systemctl enable --now domainblock.timer
systemctl enable --now domainblock-report.timer
echo ""
echo "Done. domainblock is installed and the timer is active."
echo ""
echo "  Check it's scheduled : systemctl list-timers domainblock.timer"
echo "  Run once now         : sudo systemctl start domainblock.service"
echo "  Watch logs           : journalctl -u domainblock.service -f"
echo "  Verify write access   : systemctl show domainblock.service -p ReadWritePaths -p PrivateTmp"
echo "  Edit patterns        : $INSTALL_DIR/domainblock-patterns.txt   (no restart needed)"
echo ""
echo "  seen.csv log rotation : /etc/logrotate.d/domainblock (monthly, 6 kept)"
echo "  Monthly report timer  : systemctl list-timers domainblock-report.timer"
echo "                          (no-op until monthly_report: true is set in config.yml)"
echo "  Test the report now   : sudo -u $SERVICE_USER DOMAINBLOCK_DRYRUN=1 DOMAINBLOCK_DEBUG=1 \\"
echo "                            $RUBY_BIN $INSTALL_DIR/domainblock-monthly-report.rb"
echo ""
echo "If you haven't yet, do a manual dry-run first to confirm router connectivity:"
echo "  sudo -u $SERVICE_USER DOMAINBLOCK_DEBUG=1 $RUBY_BIN $INSTALL_DIR/domainblock.rb"
