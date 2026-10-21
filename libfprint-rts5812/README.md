# libfprint driver for RTS5812 / TDK TCFS2000 (`0bda:5812`)

A libfprint image driver for the Realtek RTS5812 fingerprint bridge, built on
the protocol reverse-engineered in [`../PROTOCOL.md`](../PROTOCOL.md)
and the hardware-verified frame crypto.

## Layout

| File | What it is | Status |
|------|------------|--------|
| `crypto/rts5812_crypto.{c,h}` | Session KDF + AES-256-CMAC verify + AES-256-CBC decrypt + open-session oracle | **verified on hardware** |
| `crypto/test_decode.c`, `crypto/Makefile` | Offline test: decode `../../frame.bin`, check keys/CMAC, write PGM | runnable now |
| `rts5812.h` | USB IDs, opcodes, DMP/session registers, framing constants | verified vs. driver |
| `rts5812_fw.h` | Embedded DMP firmware (31912 B, generated from `../dmp_fw.bin`) | verified vs. driver |
| `rts5812.c` | libfprint `FpImageDevice` driver — full bring-up, session, capture | **ported; needs a Linux compile+run pass** |

## Verify the crypto now (no device needed)

The crypto is independently testable against the captured frame:

```sh
cd crypto
make check          # needs nettle-devel (dnf) / nettle-dev (apt)
# cmac_key … ok
# ctr_key  … ok
# decode   rc=0 ok (CMAC VERIFIED)
# wrote    out.pgm (135x62)
# RESULT: PASS
```

`out.pgm` is the decrypted fingerprint. (It's real biometric data — don't commit it.)

## What `rts5812.c` now does

The driver is a complete 1:1 port of the hardware-proven Python probe
(`../rts5812_probe.py`, Fedora runs #4/#5). `dev_open` runs the full proven chain:

1. **Cold bring-up** (`rts5812_warm_dmp`): whoami → wake → hardware reset → wake →
   DMP firmware upload (embedded `rts5812_fw.h`, 511-byte chunks) → gain-comp off →
   `change_dmp_mode(1,14,5)` (with `applyCustomGenerator` before mode 5) →
   `inv_fp_start` (replays `blob[0x3C:0x3B4]` into DMP 0, pokes reg 0x0D=4) to arm
   the responder (0x0E bit 0x08).
2. **Authenticated session** (`rts5812_open_session_verified`): random 8-byte SID →
   write to DMP 0x3D0 → trigger reg 0x0D=8 → read the 16-byte reply from reg 0x87 →
   confirm it equals `AES256_CMAC_{cmac_key}(SID‖0^8)` (the crypto's new
   `rts5812_session_oracle`). Open fails loudly if the oracle disagrees.
3. **Capture** (`rts5812_capture_ssm`): `setSensorMode(1)` → poll `getImageStatus`
   (re-arm every 16 polls) → `getImageData` → verify+decrypt (CMAC) → a per-image
   2/98-percentile contrast stretch (`rts5812_normalize_stretch`, the Step B
   normalization) → hand to libfprint/NBIS.

### Compile + run pass — DONE (Fedora, 2026-10-20)

Built in-tree against libfprint 1.94.100 with GCC 16 and captured a real fingerprint
through `build/examples/img-capture`. Two fixes were needed:

1. **dev_open crash:** libfprint's `fpi_usb_transfer_submit_sync` dereferences `*error`
   unconditionally, so a NULL error pointer segfaults it. The firmware read-back verify
   passed NULL. `rts5812_cmd` now substitutes a local `GError` when handed NULL.
2. **Capture never saw a finger:** the poll loop had no delay, re-arming setSensorMode
   ~128x too fast. Now `fpi_ssm_jump_to_state_delayed(..., RTS5812_POLL_INTERVAL_MS=128)`,
   re-arming every 16 polls — matching the probe. Finger detected in ~2 s.

Build note: this box's shell has the Vivado env sourced, which exports
`CFLAGS=-std=gnu89` and breaks libfprint's C99 build. Configure/compile with
`env -u CFLAGS -u CXXFLAGS -u CPPFLAGS PATH=/usr/bin:$PATH meson ...`.

### Still open — needs the Linux box

- **`bz3_threshold` calibration** against live enroll/verify. Step B
  (`../STEP_B_RESULTS.md`) says strong same-finger pairs separate cleanly but weak
  presses need retries, so **enroll from several frames** and keep the threshold modest.
- **Optional:** confirm reference NBIS bozorth3 numbers (cheap on Fedora) and, if
  wanted, Linux-side enrollment of new fingers (`securitySessionEnroll`). Reuse of the
  existing Windows pairing already works because `K` persists in the bridge flash.

## Build inside libfprint

**Full step-by-step for the Linux box: [`BUILD_ON_FEDORA.md`](BUILD_ON_FEDORA.md).**
In short — this isn't a standalone build; libfprint drivers compile as part of the tree:

1. Copy `rts5812.c`, `rts5812.h` and `crypto/` into `libfprint/drivers/`.
2. In `libfprint/drivers/meson.build` add the sources, e.g.:
   ```meson
   drivers_sources += files('rts5812.c', 'crypto/rts5812_crypto.c')
   ```
3. Register the driver id `rts5812` in the top-level `meson.build` driver list
   (the `drivers` option / `FPI_TYPE_...` table) and ensure `nettle` is in
   `deps` (libfprint already pulls it in via gnutls on most distros).
4. `meson setup build && meson compile -C build`, then test with
   `build/examples/fp-enroll` / `fp-verify` against the plugged-in device.

## Roadmap (big picture)

```
[x] USB transport + framing          [x] session KDF / CMAC / CBC decrypt (hw-verified)
[x] offline frame decode (C + py)    [x] inv_fp_open_session (solved + hw-confirmed, ported to C)
[x] cold bring-up ported to C        [x] capture loop + image normalization ported to C
[x] compile + run inside libfprint on Linux (Fedora 2026-10-20, GCC 16, libfprint 1.94.100)
[x] live capture through the driver — img-capture produced a clean 135x62 fingerprint
[ ] NBIS bz3_threshold calibration   [ ] enroll/verify/identify validated on hardware   <- next
[ ] (optional) Linux-side enrollment of new fingers
```
