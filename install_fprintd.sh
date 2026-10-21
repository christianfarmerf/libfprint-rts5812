#!/usr/bin/env bash
# Point the system fprintd at our libfprint build (with the rts5812 driver),
# WITHOUT touching the RPM-owned /usr/lib64/libfprint-2.so.2:
#   - the library is copied to /usr/local/lib64/libfprint-rts5812/
#   - a systemd drop-in sets LD_LIBRARY_PATH for fprintd.service only
# dnf updates can't clobber it. Undo with: sudo bash uninstall_fprintd.sh
# Re-run this after rebuilding libfprint to deploy the new build.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../libfprint/build/libfprint/libfprint-2.so.2.0.0"
DEST=/usr/local/lib64/libfprint-rts5812
DROPIN=/etc/systemd/system/fprintd.service.d/rts5812.conf

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$SRC" ] || { echo "missing $SRC -- build libfprint first"; exit 1; }

# Copy, not symlink: fprintd runs with ProtectHome=true and cannot see /home.
install -D -m 0755 "$SRC" "$DEST/libfprint-2.so.2.0.0"
ln -sf libfprint-2.so.2.0.0 "$DEST/libfprint-2.so.2"
restorecon -R "$DEST" 2>/dev/null || true

mkdir -p "$(dirname "$DROPIN")"
cat > "$DROPIN" <<CONF
# rts5812 fingerprint driver: load the custom libfprint build (see
# ~/Documents/REA/linux-driver/install_fprintd.sh). Remove this file to revert.
[Service]
Environment=LD_LIBRARY_PATH=$DEST
CONF

systemctl daemon-reload
systemctl stop fprintd.service || true   # D-Bus activation restarts it with the new env

echo "Installed. Checking fprintd sees the sensor..."
fprintd-list "${SUDO_USER:-root}" || true
