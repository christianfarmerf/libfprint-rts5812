# RTS5812 fingerprint reader on Linux

A Linux driver for the Realtek RTS5812 fingerprint bridge with a TDK TCFS2000
sensor (USB `0bda:5812`), found built into some laptops. Realtek only ships a
Windows driver (`RtsWBDI.dll`, Windows Hello / WBDI). This project reverse
engineers that driver's protocol and implements it as a libfprint driver, so
the reader works with fprintd: `sudo`, login, and the GNOME lock screen.

## Status

Working on hardware (Fedora, GNOME Shell 50, libfprint 1.94.100):

- Device bring-up: firmware upload, sensor modes, the encrypted session handshake
- Capture and decryption of 135x62 frames (AES-256 CBC with a CMAC tag)
- Enroll (12 presses) and verify through fprintd, including `sudo` and the lock screen
- Lock screen after suspend, using a small libfprint core patch
- Touch-to-unlock from the lock screen's clock view, using a GNOME Shell extension

The sensor area is small (about 7x3 mm), too small for minutiae matching, so the
driver matches on the host with its own keypoint matcher (`rts5812_match.c`).
Matching follows how much of the finger was covered: some presses need a
second try, and enrolling the same finger again in a second slot helps. In
testing, every different-finger attempt was rejected.

## Layout

| Path | What it is |
|------|------------|
| `PROTOCOL.md` | Reverse-engineered protocol notes: USB framing, registers, firmware, session crypto |
| `libfprint-rts5812/` | The libfprint driver (C), the matcher, the frame crypto, and libfprint patches |
| `libfprint-rts5812/BUILD_ON_FEDORA.md` | Build, install and test instructions |
| `libfprint-rts5812/README.md` | Driver design notes |
| `gnome-extension/` | Fingerprint Wake, a GNOME Shell extension for touch-to-unlock on the lock screen |
| `rts5812_probe.py`, `rts5812_decode.py` | Standalone Python userspace driver (pyusb) used to prove the protocol |
| `PROBE.md` | Probe usage and bring-up history |
| `rts5812_match.py`, `rts5812_pymatch.py`, `STEP_B_RESULTS.md` | Offline match-viability study |
| `prototypes/minikp.py` | Python prototype of the keypoint matcher that the C version was checked against |
| `dmp_fw.bin` | DMP firmware for the bridge, extracted from `RtsWBDI.dll` (also embedded as `rts5812_fw.h`) |
| `install_fprintd.sh`, `uninstall_fprintd.sh` | Point the system fprintd at the patched libfprint build |
| `fprintd_debug.sh` | Turn fprintd debug logging on or off |
| `test_enroll_verify.sh`, `capture_dataset.sh` | Hardware test helpers |

## Quick start

The driver is built inside a libfprint source tree. The build instructions
expect this repository and the libfprint checkout to sit side by side, with
this one named `linux-driver`:

```sh
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
git clone <this repository> linux-driver
```

Then follow `libfprint-rts5812/BUILD_ON_FEDORA.md`. In short: copy the driver
sources into `libfprint/libfprint/drivers/`, apply
`libfprint-add-rts5812-driver.patch` and `libfprint-defer-open-while-suspended.patch`,
build with meson, test with `test_enroll_verify.sh`, then run `install_fprintd.sh`.

Build dependencies on Fedora: `sudo dnf builddep libfprint` plus
`sudo dnf install nettle-devel meson ninja-build git`.

## Firmware

`dmp_fw.bin` and `rts5812_fw.h` contain Realtek's firmware for the bridge's DMP
core, copied unmodified from `RtsWBDI.dll` 10.0.19041.27 (sha256 of the blob:
`d55b50a8c853ac459815e8bcd8473f7741c3f6242a63e1a83fc7e4955e522956`). The
firmware belongs to Realtek; it is included only so the device can be used.

## Not included

No fingerprint captures, debug logs, Windows driver binaries or decompiler
output are in this repository. The capture scripts write their frames to
directories that `.gitignore` excludes.
