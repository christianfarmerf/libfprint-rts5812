#!/usr/bin/env bash
# Hardware test of the FpDevice driver: enroll one finger, then verify repeatedly.
# Usage: sudo bash test_enroll_verify.sh            (enroll, then verify)
#        sudo bash test_enroll_verify.sh --verify   (verify only, keep enrollment)
# Run in a real terminal. GLib prints debug (scores, coverage) on stdout, so each
# session is recorded with script(1) into enroll_fpdev.log / verify_fpdev.log.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../libfprint"

if [ "$1" != "--verify" ]; then
  # Old enrollments may be NBIS prints from the image-device driver; set them aside.
  [ -f test-storage.variant ] && mv test-storage.variant "test-storage.variant.old.$(date +%s)"
  echo "=== ENROLL: pick a finger; 12 presses, lift fully, shift placement a little each time ==="
  script -q -f -c ./build/examples/enroll "$HERE/enroll_fpdev.log"
  echo
fi

echo "=== VERIFY: pick the enrolled finger. Answer Y to repeat. Do ~8 tries with the"
echo "    enrolled finger, then ~8 with a DIFFERENT finger (should all be NO MATCH) ==="
script -q -f -c ./build/examples/verify "$HERE/verify_fpdev.log"

chown "${SUDO_USER:-$USER}" "$HERE"/*_fpdev.log test-storage.variant 2>/dev/null || true
echo "Results:"; grep -aoE "verify score -?[0-9]+|NO MATCH!|MATCH!|not centered" "$HERE/verify_fpdev.log" || true
