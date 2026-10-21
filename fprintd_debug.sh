#!/usr/bin/env bash
# Toggle libfprint/fprintd debug logging (goes to the journal) for the rts5812 install.
# Usage: sudo bash fprintd_debug.sh on|off      then: journalctl -u fprintd -b
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
F=/etc/systemd/system/fprintd.service.d/rts5812-debug.conf
case "${1:-}" in
  on)  printf '[Service]\nEnvironment=G_MESSAGES_DEBUG=all\n' > "$F" ;;
  off) rm -f "$F" ;;
  *)   echo "usage: $0 on|off"; exit 2 ;;
esac
systemctl daemon-reload
systemctl restart fprintd.service   # also clears a stuck claim
echo "fprintd debug $1"
