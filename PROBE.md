# RTS5812 fingerprint — Linux userspace probe

`rts5812_probe.py` is a standalone userspace driver skeleton for the Realtek
RTS5812 fingerprint bridge (USB `0bda:5812`, TDK TCFS2000 sensor), built from the
protocol reverse-engineered out of the Windows driver (`PROTOCOL.md`). It
talks to the device with libusb (pyusb), so there is nothing to compile.

Run on **Linux** (a live USB is fine), where the device is not held by the
Windows Hello (WBDI) driver. Avoid Windows: freeing the device for libusb there
(e.g. Zadig → WinUSB) disables Windows Hello until the original driver is
restored.

## Current step — the libfprint C driver (match-viability test passed)

**The userspace pipeline is complete and hardware-confirmed end to end** (Fedora run #5,
2026-10-20). `sudo python3 rts5812_probe.py --reset --warm-dmp --open-session --capture
frame.bin` ran clean from cold and produced `<== MATCH`, `SESSION OPEN CONFIRMED`,
`CMAC VERIFIED`, and a 135×62 `frame.pgm` that shows a **real fingerprint** — clear
curving ridges with a loop-ish core. Every stage (transport, framing, firmware upload,
modes 1/14/5, `inv_fp_start` arm, `open_session` handshake, capture, decrypt) is now
proven on hardware. See the run log at the bottom.

The protocol risk is gone. The one risk left before committing to the C driver is
**biometric**: are these small (135×62), low-contrast (std ≈ 6.3) frames good enough to
enroll and match under libfprint's matcher (NBIS mindtct + bozorth3)? We answer that
*before* writing the driver, so an enrollment failure later can't be confused with a
driver bug — and so we know what image normalization (if any) to bake in. (Visual check
already done: the raw frame is faint, but a global stretch or a simple local-equalize
makes ridges crisp — see `rts5812_match.py`.)

### Step A — capture several frames (next Fedora trip)

The probe now does multi-capture. Grab a few presses of one finger, then a few of a
**different** finger (so we can test both genuine matches and impostor rejection). Lift
between presses; it waits for a clean lift before arming the next:

```sh
# 4 presses of the index finger
sudo python3 rts5812_probe.py --reset --warm-dmp --open-session \
    --capture frame.bin --captures 4 --label index
# 3 presses of a different finger (middle/thumb) — re-run the whole chain
sudo python3 rts5812_probe.py --reset --warm-dmp --open-session \
    --capture frame.bin --captures 3 --label middle
```

This writes `frame_index01..04.{bin,blob,pgm,json}` and `frame_middle01..03.{...}`.
**Send me all the `frame_index*` and `frame_middle*` files** (the `.bin` + `.bin.blob`
are enough; `.pgm` is handy for a quick look). Press firmly; re-run any press that
reports *near-flat*.

### Step B — offline match test — **DONE (2026-10-20): identity recoverable**

`rts5812_match.py` decrypts every frame, builds normalization variants (`raw`,
`stretch`, `loceq`), reports a ridge-coherence metric, and runs a match backend:
`mindtct` + `bozorth3` where NBIS is installed, otherwise the **pure-Python backend**
(`rts5812_pymatch.py`) that answers the same question without a C toolchain.

```sh
python3 rts5812_match.py frame_index*.bin frame_middle*.bin --out match_out
```

**Result (full writeup: [`STEP_B_RESULTS.md`](STEP_B_RESULTS.md)):** on the 7 live
frames, **6/7 presses correctly identify their own finger** over a different finger
(ridge-correlation; strong same-finger pairs 0.72–0.82 vs impostor ceiling 0.57;
AUC 0.61, d′ 0.75). The images are good; the only failure (`middle03`) is a weak
press, not an image defect — the limiting factor is capture *overlap* on a small
platen. **Decisions for Step C:** bake in a per-image contrast normalization (global
`stretch` suffices), enroll from multiple frames, let NBIS extract minutiae, and gate
out near-flat/low-coherence presses. Reference bozorth3 is expected to pass and is a
cheap confirmation on the next Fedora trip (NBIS installs trivially there).

Needs `numpy`, `pillow` (+`pycryptodome` to read `.bin`); auto-detects `mindtct`/
`bozorth3` on PATH and falls back to the Python backend otherwise.

### Step C — libfprint C driver

With matching de-risked, the driver is a mechanical port of the proven Python
(transport, framing, firmware upload, modes, `inv_fp_start`, `open_session`, capture
state machine, decode), plus whichever normalization Step B picks. No further
reverse-engineering needed.

### Re-running a single live capture (reference)

Run the full chain and touch the sensor when it says to (15 s; `--timeout N` to extend):

```sh
sudo python3 rts5812_probe.py --reset --warm-dmp --open-session --capture frame.bin
```

- `frame ready after N polls; reading image...` — `getImageStatus` returned 1 on touch.
- `CMAC VERIFIED (session keys correct, frame authentic)` — the definitive oracle: the
  live frame decrypts with keys derived from its own SID + the device master key.
- `image 135x62 -> frame.pgm: ...` then `=> LIVE CAPTURE OK`. Open `frame.pgm` (any
  image viewer, or `eog frame.pgm`) and you should see ridges.

If it says *no finger detected*, re-run and press firmly and promptly. If it decrypts
but reads *near-flat (blank platen)*, the capture works but the finger wasn't imaged —
press harder. A `CMAC MISMATCH` would mean the blob/SID disagree with the frame
(shouldn't happen — the blob self-checks).

The detail below documents the solved handshake and stays as reference.

---

The handshake is fully solved from the DLL. The last Fedora run showed the modes
`1,14,5` take `0x0E` to `0x22` (bit `0x20` set) but **never** set bit `0x08`, so
`inv_fp_open_session` returns `-5` and the old sweep only echoed our own SID back
out of DMP RAM. Reading the disassembly settled why, and pinned the two registers
Ghidra had dropped:

- **The responder is armed by `inv_fp_start`, not the modes.** `setupDevice`
  reaches it right after "Finished DMP" (mode 5), as the `securitySessionStart`
  step. It replays the **0x378-byte per-device start material `blob[0x3C:0x3B4]`**
  into **DMP address 0**, then pokes **`write_reg8(0x0D, 4)`**. *That* is the step
  that flips `0x0E` bit `0x08`. Its precondition is exactly the `bit 0x20` state
  the modes leave. The probe now runs it automatically at the end of `--warm-dmp`.
- **`inv_fp_open_session` trigger = `write_reg8(0x0D, 8)`** (same register, value
  8), after the SID write to `0x3D0`.
- **The response is `read_reg(0x87, 16)`** — a direct sensor-register read, *not*
  a `read_dmp_mem` of `0x3D0`. That is why the old sweep never matched. Between the
  trigger and the read it waits for `(read_reg8(0x39) & 4) == 0`.

`--open-session` now runs this exact sequence and checks the reply against the
oracle, so a correct arm should print `<== MATCH` on the first (only) attempt.

### Do this on the Fedora machine

1. Install deps if not already present:
   ```sh
   python3 -m pip install pyusb pycryptodome
   ```
2. Run (as root, or with a udev rule granting access). `--reset` re-enumerates the
   device in software to clear any aborted bring-up — no replug needed (this is a
   laptop with a built-in sensor):
   ```sh
   sudo python3 rts5812_probe.py --reset --warm-dmp --open-session --sweep
   ```
3. **Send me the full output.**

### What to watch for (in order)

- `firmware upload verified (31912 bytes)` — the DMP firmware made it across.
- `inv_fp_start (blob[0x3c:]-> DMP 0, w(0x0d,4)) ok` — the arming step ran.
- `0x0E start ... <-- SERVICEABLE` — `inv_fp_start` flipped `0x0E` into the state
  `inv_fp_open_session` needs (bit `0x08` set, `0x40` clear). The responder is
  armed. (Watch the `0x0E start` line specifically — that's the one `inv_fp_start`
  should move from `0x22`.)
- `w(0x0d,8) -> read_reg(0x87,16) -> … <== MATCH` — the sensor's reply reproduced
  the auth oracle. **This is the result we want**: the fresh-SID handshake works.

`dmp_fw.bin` ships next to the script (0x7CA8 bytes extracted from RtsWBDI.dll
`0x180148be0`, sha256 `d55b50a8…522956`); pass `--fw PATH` to override.

### The DMP-upload STALL — fixed

The upload kept failing with `op 0x61 (reg=0xc len=…): Pipe error (errno 32)` on
the first DMP data chunk. The data points settle the cause: both a `0x4000` and a
`0x3FFF` chunk STALL the bulk-OUT pipe on that first `0x0C` write, while every
≤4-byte register write succeeds. So the earlier "exact-multiple-of-512 leaves no
short packet" theory was wrong (`0x3FFF` isn't a 512-multiple and still stalled).
The bridge's `writeReg` handler simply won't accept a payload anywhere near 16 KB.

The Windows driver bounds every `serial_write(0x0C)` to `max_xfer - 1` bytes
(`inv_fp_write_dmp_mem`, PROTOCOL.md), and `max_xfer` is the bulk endpoint's max
packet — 512 on high speed. So the real chunk is **`0x1FF` (511 bytes)**: at most
one packet of sensor data per `writeReg`. That is now the default in
`rts5812_probe.py`; the firmware uploads in ~63 chunks (still milliseconds).

If a DMP write *still* STALLs on this hardware, step the chunk down further.
`--reset` clears the aborted bring-up at the start of each run, so no replug is
needed between attempts:
```sh
sudo python3 rts5812_probe.py --reset --warm-dmp --open-session --sweep --dmp-chunk 0xFF
```
A pipe error also clears the endpoint halt and reports which command failed
(instead of a raw traceback). If `--reset` can't re-enumerate for some reason, a
full power-off shutdown (not a reboot, and not with Windows Fast Startup) also
resets the sensor.

### If there's no MATCH

Read the `0x0E start`/`0x0E after` lines first — they decide the next move:

- **If `0x0E` shows `<-- SERVICEABLE` (bit `0x08` set, `0x40` clear) but still no
  MATCH:** the responder is armed and the handshake ran, so the KDF/oracle
  disagrees with the sensor's reply. That's unlikely — the KDF is already
  blob-self-verified — but if it happens, send me the full `w(0x0d,8) ->
  read_reg(0x87,16)` line; a Windows USB log of one `securitySessionOpen` would
  pin any remaining difference.
- **If `inv_fp_start` printed an error, or `0x0E start` is not serviceable** (e.g.
  it errored on `bit0x20 clear`, meaning the modes didn't reach `0x22` this time):
  the arm didn't take. Send me the output — the most likely culprits are the
  bring-up pieces still skipped (trim/OTP load, step 6; timer0 config, step 8),
  which may be needed before the modes land in the `0x20` state.

Prior art from the last run: `0x42 --mode(1)--> 0x22`, then flat through modes 14
and 5. `inv_fp_start` is the step that should now move `0x22 -> serviceable`.

## Status

- [x] USB transport + command framing (verified byte-accurate vs. the driver)
- [x] confirmed against hardware (probe + capture ran on a real `0bda:5812`)
- [x] image frame decryption — **SOLVED and hardware-verified**: session KDF from
      `K = blob[0x1C:0x3C]` + the frame SID, AES-256-CMAC tag verifies, AES-256-CBC
      yields a clean 135×62 fingerprint.
      Decode offline: `python3 rts5812_decode.py frame.bin --blob frame.bin.blob`
- [x] sensor bring-up from cold (DMP firmware upload + modes `1,14,5`) — firmware
      upload verified on hardware; responder arm via `inv_fp_start` now wired in
- [x] pin `inv_fp_open_session` trigger/response — **SOLVED and hardware-confirmed**:
      arm = `inv_fp_start` (`blob[0x3C:]`→DMP 0, `w(0x0D,4)`); open trigger = `w(0x0D,8)`;
      response = `read_reg(0x87,16)`; ready-poll = `r(0x39)&4==0`. Fedora run #4
      reproduced the oracle exactly on two different fresh SIDs (`<== MATCH` both,
      default and `--dmp-chunk 0xFF`). The whole cold-boot → arm → open-session path is
      proven; the skipped trim/OTP + timer0 bring-up steps were not needed to arm.
- [x] end-to-end live capture — **DONE and hardware-confirmed** (Fedora run #5):
      `--reset --warm-dmp --open-session --capture` from cold gave `<== MATCH`,
      `SESSION OPEN CONFIRMED`, finger detected after 14 polls, `CMAC VERIFIED`, and a
      135×62 `frame.pgm` showing a real fingerprint (clear curving ridges). Image
      contrast is low (std ≈ 6.3) — ridge structure is solid but a per-image gain/
      contrast normalization (as the Windows driver does) would improve match quality.
- [ ] libfprint C driver — only remaining work; a mechanical port of the now
      fully-proven Python (transport, framing, fw upload, modes, inv_fp_start,
      open_session, capture state machine, decode). Optional: image contrast normalize.

chris@fedora:~/Documents/linux-driver$ sudo python3 rts5812_probe.py --reset --warm-dmp --open-session --capture frame.bin
[sudo] password for chris: 
found 0bda:5812
issued USB port reset; waiting for re-enumeration...
[rts5812] endpoints: bulk_out=0x01 bulk_in=0x82 interrupt_in=['0x83', '0x84']
image_status  -> 0x00  (command framing OK)
read_reg(0x00,1) -> ad
read_reg(0x80,1) -> ad
session_key(32)  -> 54434653492ed64da301f74fe5b30a5409d84546401c3c1805bf52fee199a6d4

--warm-dmp: bringing up the DMP to arm the session responder
  firmware  = /home/chris/Documents/linux-driver/dmp_fw.bin (31912 bytes)
  whoami    = 0xad
  0x0E before    = 0x42  (idle=1 bit0x08=0 bit0x40=1)
[rts5812] firmware upload verified (31912 bytes)
  fw version= 040700001912050014150400
  change_dmp_mode_with_completion(1) ok
  0x0E mode1     = 0x22  (idle=1 bit0x08=0 bit0x40=0)
  change_dmp_mode_with_completion(14) ok
  0x0E mode14    = 0x22  (idle=1 bit0x08=0 bit0x40=0)
  applyCustomGenerator (dmp[0x16E18]=0x5A) ok
  change_dmp_mode_with_completion(5) ok
  0x0E mode5     = 0x22  (idle=1 bit0x08=0 bit0x40=0)
  inv_fp_start (blob[0x3c:]-> DMP 0, w(0x0d,4)) ok
  0x0E start     = 0x0a  (idle=1 bit0x08=1 bit0x40=0)  <-- SERVICEABLE
  0x0E after     = 0x0a  (idle=1 bit0x08=1 bit0x40=0)  <-- SERVICEABLE
  => responder ARMED (0x0E serviceable)

--open-session: running inv_fp_open_session
  K = e199a6d4750b588b60c47abfa9a6f5ff4668144b5ba4fc1050c2fa485a7fc351
  DMP status 0x0E = 0x0a (bit0x08=1 bit0x40=0)  <-- SERVICEABLE
  SID       = fc3b5c3ccc862bd2
  oracle    = 18bf22a846e5ecb4e438484a5b25d33e  (expected sensor reply)
  w(0x0d,8) -> read_reg(0x87,16) -> 18bf22a846e5ecb4e438484a5b25d33e <== MATCH

  SESSION OPEN CONFIRMED
  trigger   = write_reg8(0x0d, 8)
  response  = read_reg(0x87, 16)
  cmac_key  = 0034c2eea34f276e015381f0b993e3db0e35faa39559d218316b34a22fe2d567
  ctr_key   = fd09949600417499e29a3ef13f7b04d6de2f43b5914ac5404084a77fd6ac49c2

--capture: arming sensor; place a finger on the sensor...
  frame ready after 14 polls; reading image...
  wrote 16896 bytes -> frame.bin
  wrote device-key blob (948 bytes) -> frame.bin.blob
  frame: header=fc3b5c3ccc862bd200000000 ctr=00000001 iv=6dc8e35524ace3fca98ebdfb50466b87 cmac=384db9552d9634d7e75230921f4a282d
  SID=fc3b5c3ccc862bd2  K=e199a6d4750b588b60c47abfa9a6f5ff4668144b5ba4fc1050c2fa485a7fc351
  CMAC VERIFIED (session keys correct, frame authentic)
  image 135x62 -> frame.pgm: min=92 max=129 mean=119.1 stddev=6.3 concentration=0.997
  => LIVE CAPTURE OK: authentic frame with an imaged finger (open the PGM to confirm ridges).
  wrote metadata -> frame.bin.json
done

