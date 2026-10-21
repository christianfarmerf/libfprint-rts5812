# Building + testing the RTS5812 driver on Fedora

This is the build and test checklist for the libfprint driver on Fedora. For background,
read `../PROBE.md` (the userspace probe), `../STEP_B_RESULTS.md` (match viability), and
`./README.md` (the driver design).

## 0. Sanity-check the probe still works (fast, no libfprint)

Before touching libfprint, confirm the hardware path is intact — this re-proves
everything the C driver depends on, in seconds:

```sh
cd linux-driver
python3 -m pip install --user pyusb pycryptodome
sudo python3 rts5812_probe.py --reset --warm-dmp --open-session --capture frame.bin
# expect: firmware upload verified -> <== MATCH -> SESSION OPEN CONFIRMED ->
#         CMAC VERIFIED -> frame.pgm
```

If that prints `<== MATCH` and `CMAC VERIFIED`, the bring-up/session/capture logic the
C driver mirrors is good, and any build failure below is purely a C/libfprint issue.

## 1. Confirm the crypto unit test (no device)

```sh
cd linux-driver/libfprint-rts5812/crypto
sudo dnf install -y nettle-devel gcc make
make check      # decodes ../../frame.bin -> CMAC VERIFIED, writes out.pgm
```

## 2. Matcher harness (no device)

NBIS (mindtct + bozorth3) does **not** work on this sensor: a 135x62 frame covers
~7x3 mm of finger, about 4-5 real minutiae, and every pair scores 0 even after Gabor
enhancement. The driver matches with its own keypoint + rigid-RANSAC matcher
(`rts5812_match.c`). Check it offline against the labelled dataset:

```sh
gcc -O2 test_match.c rts5812_match.c $(pkg-config --cflags --libs glib-2.0) -lm -o test_match
./test_match ../dataset2/frame_*.pgm     # prints keypoint counts and all pair scores
```

Capture a fresh labelled dataset with `sudo bash ../capture_dataset.sh 10` (real
terminal; sudo needs a tty).

## 3. Build the driver inside libfprint

```sh
# build deps (the packaged libfprint's deps cover almost everything)
sudo dnf builddep -y libfprint
sudo dnf install -y nettle-devel meson ninja-build git

git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
cd libfprint

# drop the driver in (keep crypto in a subdir so the #include path matches)
D=../linux-driver/libfprint-rts5812
cp "$D/rts5812.c" "$D/rts5812.h" "$D/rts5812_fw.h" \
   "$D/rts5812_match.c" "$D/rts5812_match.h" libfprint/drivers/
mkdir -p libfprint/drivers/crypto
cp "$D/crypto/rts5812_crypto.c" "$D/crypto/rts5812_crypto.h" libfprint/drivers/crypto/
```

Then register it. The exact meson wiring shifts between libfprint versions, so the
reliable method is to **mirror an existing simple USB image driver** (`elan` is a good
template) wherever it appears. On libfprint 1.94.100 (commit `6f9479c`), steps 1-4
are exactly `git apply ../linux-driver/libfprint-rts5812/libfprint-add-rts5812-driver.patch`;
by hand:

1. `grep -rn "elan" meson.build libfprint/meson.build libfprint/drivers/meson.build`
   to find the two spots: the **driver list** (enables the GType) and the
   **sources list**.
2. Add `rts5812` alongside `elan` in the driver list.
3. Add the sources alongside elan's, e.g. in the drivers sources:
   ```meson
   'rts5812' : files('drivers/rts5812.c', 'drivers/rts5812_match.c',
                     'drivers/crypto/rts5812_crypto.c'),
   ```
4. Add `nettle_dep = dependency('nettle', version: '>= 3.6')` in the top-level
   meson.build and list `nettle_dep` in libfprint/meson.build's deps (the matcher
   also needs `mathlib_dep`, which libfprint already links).

5. Apply the libfprint core patch (needed for the lock screen after suspend):
   `git apply ../linux-driver/libfprint-rts5812/libfprint-defer-open-while-suspended.patch`.
   Without it, a claim that races system suspend (the lock screen appearing as the
   lid closes) fails with BUSY and GNOME never retries fingerprint after resume; with
   it the open waits for resume. It includes a unit test (`meson test -C build fpi-device`).

Build + run:

```sh
# the Vivado env exports CFLAGS=-std=gnu89, which breaks libfprint: build clean
env -u CFLAGS -u CXXFLAGS -u CPPFLAGS PATH=/usr/bin:$PATH meson setup build
env -u CFLAGS -u CXXFLAGS -u CPPFLAGS PATH=/usr/bin:$PATH meson compile -C build
# enroll + verify against the plugged-in sensor, with scores logged:
sudo bash ../linux-driver/test_enroll_verify.sh            # enroll, then verify
sudo bash ../linux-driver/test_enroll_verify.sh --verify   # verify only
```

GLib prints debug messages (scores, coverage) on **stdout**, so the script records
each session with `script(1)` rather than redirecting stderr.

Device access: either run the examples with `sudo`, or add a udev rule granting your
user access to `0bda:5812` (see libfprint's `meson_options`/`udev` or copy an existing
`70-fingerprint.rules` pattern) so the examples run unprivileged.

## 4. How matching works / what to tune

- **FpDevice, host-side matching.** Enroll captures `RTS5812_ENROLL_STAGES` (12)
  presses and stores the raw frames in the print (`FPI_PRINT_RAW`, GVariant
  `(qqqaay)` = format, w, h, frames). Verify/identify compare a new frame against
  each stored frame and stop at the first that clears the threshold. Storing raw
  frames means matcher changes never invalidate enrollments.
- **Score = inliers** of the best rigid (rotation + shift) RANSAC fit between keypoint
  matches. `RTS5812_MATCH_THRESHOLD` = 8. On hardware (2026-10-20, 12-frame
  enrollment, 2 px tolerance): genuine 8-42 (9/9 matched), different finger 4-7 (15/15
  rejected). The tolerance has since dropped to 1.5 px, which lowers the
  different-finger floor by about one inlier.
- **Coverage is the limit, not the matcher.** A press that lands on finger area no
  enrolled frame saw cannot match. Enroll with varied placement; offline, false
  rejects fall steadily as more presses are enrolled.
- **Quality gate:** ridge coverage (fraction of 8x8 blocks with contrast) must be
  >= 0.55 to enroll and >= 0.20 to match; failing presses get a "center finger" retry.
- **libfprint API drift:** if a newer tree breaks the build, compare the action
  reporting (`fpi_device_*_report/complete`) against `drivers/virtual-device.c`.

## 5. Line endings

Files copied from Windows may have CRLF. C and Python don't care, but if any shell
step misbehaves: `sed -i 's/\r$//' <file>` or `dos2unix linux-driver -r`.
