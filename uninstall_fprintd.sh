#!/usr/bin/env bash
# Revert install_fprintd.sh: fprintd goes back to the stock RPM libfprint.
# Prints enrolled with the rts5812 driver stay in /var/lib/fprint but are unusable
# by the stock library (it has no rts5812 driver); delete them with fprintd-delete
# first if you want a clean slate.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
rm -f /etc/systemd/system/fprintd.service.d/rts5812.conf /etc/systemd/system/fprintd.service.d/rts5812-debug.conf
rmdir --ignore-fail-on-non-empty /etc/systemd/system/fprintd.service.d 2>/dev/null || true
rm -rf /usr/local/lib64/libfprint-rts5812
systemctl daemon-reload
systemctl stop fprintd.service || true
echo "Reverted to the stock libfprint."
