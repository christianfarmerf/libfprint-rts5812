#!/usr/bin/env bash
# Capture a labelled multi-finger dataset for offline matcher evaluation.
# Usage: sudo bash capture_dataset.sh [presses-per-finger]
# Lift fully between presses; vary placement a little, as in normal use.
set -e
cd "$(dirname "$0")"
N=${1:-10}
mkdir -p dataset2
for f in rindex rmiddle rthumb; do
  read -rp ">>> Next finger: $f ($N presses). Press Enter when ready... " _
  python3 rts5812_probe.py --reset --warm-dmp --open-session \
      --capture dataset2/frame.bin --captures "$N" --label "$f" --timeout 30
done
chown -R "${SUDO_USER:-$USER}" dataset2
echo "done: $(ls dataset2/*.bin | wc -l) frames in dataset2/"
