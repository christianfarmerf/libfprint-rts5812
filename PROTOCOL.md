# Realtek RTS5812 + TDK TCFS2000 fingerprint (USB 0bda:5812) — protocol notes

Source: RtsWBDI.dll 10.0.19041.27 (sha256 7412fca5…7f6e), decompiled with REA 6.7.0 + Ghidra 12.1.4.
Addresses are RVAs + 0x180000000 in that DLL.

## USB transport (CUsbDev, 0x1800b4xxx)
- Interface 0. Pipes: interrupt IN 0x83 ("Interrupt1"), interrupt IN 0x84 ("Interrupt2"),
  one bulk IN, one bulk OUT (addresses assigned at runtime from the descriptor).
- Bulk read/write: WdfUsbTargetPipe{Read,Write}Synchronously, timeout 4 s.
- Control: WdfUsbTargetDeviceSendControlTransferSynchronously, timeout 5 s
  (callers: CBioDev::OnControlTrans4D0 0x1800b0d40, 0x1800b3ec8 — firmware update path).
- vtable 0x1801451b8 = [bulk_read, bulk_write]; all SerialDeviceSLWINUSB commands go over bulk.

## Command framing (SerialDeviceSLWINUSB, 0x1800b7xxx–0x1800b8xxx)
Every command is the same three-phase bulk exchange, serialized by a critical section:

1. bulk OUT: 8-byte header `F0 <op> 00 00 <reg> 00 <len lo> <len hi>`
2. data phase: bulk OUT `len` bytes (write ops) or bulk IN `len` bytes (read ops)
3. bulk IN: 5-byte status; byte 0 == 0x00 means success, otherwise "status error %d"

| op   | method                 | data phase      | template addr |
|------|------------------------|-----------------|---------------|
| 0xE1 | readReg(reg, len)      | IN  len bytes   | 0x1801bb058 |
| 0x61 | writeReg(reg, buf,len) | OUT len bytes   | 0x1801bb060 |
| 0x62 | getImageData(len)      | IN  len bytes   | 0x1801bb068 |
| 0x63 | getImageStatus()       | IN  1 byte; 1 = "sensor interrupt was triggered" | 0x1801bb070 |
| 0xE4 | setSensorMode(mode)    | OUT 1 byte (len fixed 1) | 0x1801bb078 |
| 0x68 | storeSecSessionKey     | OUT len bytes (bridge flash) | 0x1801bb090 |
| 0xE8 | retrieveSecSessionKey  | IN  len bytes   | 0x1801bb098 |
| 0x64, 0x65 | templates present, unreferenced | | 0x1801bb080/88 |

readImage() = getImageStatus(); if it returns 1 → getImageData(len).
Key store/retrieve live on a second interface (this-8, "DeviceKeyInterface").

## TDK sensor register access (inv_fp layer, statically linked)
The bridge forwards readReg/writeReg to the TDK sensor (SPI-style addressing):

- `serial_read(reg, buf, n)`  → readReg  (F0 E1)  — `reg` is the raw address byte
- `serial_write(reg, buf, n)` → writeReg (F0 61)
- `read_reg8(r)`  = serial_read(r | 0x80, 1)      (0x1800ba7a8; get_whoami 0x1800b9bf0 is identical)
- `write_reg8(r,v)` = serial_write(r, [v], 1)     (0x1800ba9b0)
- `dev->max_xfer` (dword at inv_fp+0) bounds chunks to max_xfer-1 bytes.

DMP memory (sensor MCU address space):
- `write_dmp_mem(addr, buf, n)` (0x1800ba43c): serial_write(0x08, addr as 4 bytes LE); then chunks → serial_write(0x0C, chunk)
- `read_dmp_mem(addr, buf, n)`  (0x1800ba37c): serial_write(0x08, addr LE32); then chunks ← serial_read(0x8C, chunk)

Primitives:
- whoami: read_reg8(0x00) must be 0xAD
- hardware_reset (0x1800ba118): w(0x3A,0x02); sleep 2ms; w(0x04,0x3F); sleep 1ms
- lp_mode_set(en) (0x1800ba2fc): w(0x01, en?1:0); if !en: sleep 5ms; poll r(0x39) bit1 set, ≤10×1ms, else -3
- wait_irq(n) (0x1800ba908): poll r(0x03) == 1, 1ms apart, ≤n tries, else -3
- dmp_halt (0x1800ba0c8): loop { v=r(0x39); if v&4 break; w(0x04,0x20) }   (no timeout in original)
- wait_dmp_idle (0x1800ba89c): ≤100× { v=r(0x0E); if (v&5)!=1 break; sleep 1ms }; v&1 → -3; ok iff (v&6)==2
- dmp_start (0x1800b9ff8): w 1B=60 10=00 11=00 12=01 14=04 15=00 16=01 18=08 19=00 1A=01 7C=01
- load_dmp_firmware(fw,len) (0x1800ba190): w(0x04,0x01); write_dmp_mem(0x10000, fw); read back + memcmp;
  dmp_start; w(0x3E,0x04).   Firmware blob: RtsWBDI.dll 0x180148be0, 0x7CA8 bytes.
- bypass_gain_comp_enable(en) (0x1800b9d64): dmp[0x16AAF] = en ? 3 : 0
- change_mode_simple(m) (0x1800b9d8c): dmp_halt; wait_dmp_idle; w(0x1D,m); if m∈{5,12,20}: w(0x55,0)
- change_dmp_mode_with_completion(m) (0x1800b9df0):
    if m∈{5,12,20}: w(0x1D,m); wait_irq(500); if r(0x55)==1 { dmp_halt; w(0x55,0); wait_irq(500) }; wait_dmp_idle
    else: change_mode_simple(m); wait_irq(500)

## Sensor bring-up (UPrintDeviceCtrl::setupDevice 0x1800b9510)
1. whoami == 0xAD; read_device_uid
2. lp_mode_set(0). If preSetup() says "already initialized" → skip to security session.
3. hardware_reset; lp_mode_set(0)
4. load_dmp_firmware(blob, 0x7CA8); read_dmp_mem(0x16964, 12) = fw version (+ algo version)
5. bypass_gain_comp_enable(0)
6. if trim data present: overrideOTPConfiguration(); load_trim_comp_data(data, len)
7. optional sensor noise: write_dmp_mem(0x16ABC, 4 bytes)
8. timer0: read dmp 0x16AA0/0x16AA4 (4 bytes each); optional override writes
9. change_dmp_mode_with_completion(1); then (14); applyCustomGenerator(); then (5)
10. security session: retrieveDeviceKey (bridge F0 E8) → isSecurityInSession / isAllowDeviceEnroll →
    securitySessionEnroll | securitySessionStart → securitySessionOpen

## Capture + image decode (CBioDev / UPrintDeviceCtrl)
- Capture thread (0x1800b26b0): setupDevice if needed; setSensorMode(1); loop every 128 ms:
  TryToCompleteCaptureRequestEx → getImageStatus(); on 1, complete the WDF request. Re-arm
  setSensorMode(1) every 16 iterations.
- CompletePendingRequest (0x1800aeedc): readImage(buf, 0x4200) → the 0x4170-byte frame, then
  decodeFingerprintImage → hand the plaintext image to the WinBio engine adapter. Debug builds
  also dump C:\RealTek\TDK-*.{bin,pgm} (saveImage2PGM, only if C:\Realtek\WBDI\ exists).
- Image sizes: encrypted frame 0x41A0 in / 0x4170 plaintext out; PGM header "P5\n... 1 5...6..." .

## Image encryption (iid_* / iidconfidentio.c)
decodeFingerprintImage → iid_VerifyAndDecrypt(ctx, len=0x41A0, out, &outlen) at 0x1800c1140.
This is a standard AES construction, confirmed by the tables in .rdata:
- AES inverse S-box at 0x180156b30 (52 09 6a d5 ...), AES T-tables at 0x180154b30 / 0x180154f30 /
  0x180155330 / 0x180155730, key-schedule in FUN_1800c2d00 (10/12/14 rounds → AES-128/192/256).
- Layout: [12-byte header incl. 4-byte LE counter | 16-byte CMAC tag? | ciphertext | ...].
  FUN_1800c15f0 = AES-CMAC (subkey doubling with the 0x87 GF(2^128) constant) over the header;
  FUN_1800c2a80 = AES-256-**CBC** decrypt of the body (NOT CTR — see correction below).
  A monotonic 4-byte counter (_DAT_1801bc82c, stored big-endian) gives replay protection;
  0xFFFFFFFF is rejected.
- The AES key = the per-device SESSION KEY negotiated once and kept in the RTS5812 bridge flash:
  readable with retrieveSecSessionKey (F0 E8) and written with storeSecSessionKey (F0 68).
  Source strings: "master secret"/"key expansion"/"client finished"/"server finished" (a TLS-PRF
  style KDF) plus an RSA-2048 "FingerPrint Client" cert and ECDH material embedded at resource 110.

## Security session — SOLVED (securitySessionOpen 0x1800b9204, iid 0x1800c13e0/0x1800c1c00)
The "session key" read by retrieveSecSessionKey is the **948-byte (0x3B4) device-key blob** tagged
"TCFS" (retrieveDeviceKey 0x1800b89e4 reads 0x3B4 bytes). The blob is loaded to obj+0x8; the iid
context sits at obj+0x24. **Blob layout is fully mapped and hardware-verified** (offsets are blob-
relative; add 0x8 for the obj offsets used by securitySessionOpen):

    [0x00:0x04]  "TCFS" magic                                    (obj+0x08)
    [0x04:0x0C]  SID — current 8-byte session id                 (obj+0x0C, = pbVar1)
    [0x0C:0x1C]  session auth response, 16 B                     (obj+0x14)
                 = AES256_CMAC_{cmac_key}(SID || 0^8)  (the inv_fp_open_session reply)
    [0x1C:0x3C]  master key K, 32 B (AES-256)                    (obj+0x24, = iid ctx)
    [0x3C:…]     remaining per-device material

- **Master key K** = 32 bytes at **blob offset 0x1C**. Set once at enrolment by securitySessionEnroll
  (inv_fp_enroll → iid_Descramble 0x1800c0f30) and persisted in 5812 flash.
- **Per-session keys** (iid_VerifySessionOpen 0x1800c13e0): pick a random 8-byte **SID**, then
    cmac_key = KDF(mode=2, SID, K)        ctr_key = KDF(mode=1, SID, K)      (each 32 B, AES-256)
- **KDF** (FUN_1800c1c00) = SP800-108-style AES-256-CMAC over a 16-byte block, two counter iters:
    block(i) = 00 | i | mode | 00 | SID[0:8] | 00 00 | 01 | 00      (i = 0 then 1)
    out[0:16] = AES256_CMAC_K(block(0)) ;  out[16:32] = AES256_CMAC_K(block(1))
- **Session auth oracle**: AES256_CMAC_{cmac_key}( SID || zero-pad to 16 ) must equal the 16 bytes
  the sensor returns from inv_fp_open_session.
  **VERIFIED OFFLINE (2026-10-19):** computing this oracle from blob SID + K reproduces
  blob[0x0C:0x1C] EXACTLY (ab6a993e…06bccc88 for the captured device) — a second independent proof
  of the KDF, alongside the frame CMAC. So the blob alone validates K + KDF with no device.

### Arming the responder: inv_fp_start (FUN_1800ba820, = securitySessionStart) — SOLVED
This is the step that was missing: the change_dmp_mode(1,14,5) sequence only takes reg 0x0E to 0x22
(bit 0x20 set); it never sets bit 0x08, so inv_fp_open_session returns -5. The responder is armed by
**inv_fp_start**, the securitySessionStart step, which setupDevice reaches right after "Finished DMP"
(mode 5) via retrieveDeviceKey → isAllowSessionStart → securitySessionStart. Its buffer arg is
devctrl+0x44 = blob+0x3C (retrieveDeviceKey loads the 0x3B4-byte blob at devctrl+0x8), i.e. the
**0x378-byte per-device start material blob[0x3C:0x3B4]** — the "remaining per-device material".
Sequence (from the raw asm, Ghidra dropped the inv_write_reg8 immediates):
  1. wait_dmp_idle → v. If (v & 0x20): do step 2–4. Elif (v & 0x0A)==0x0A: already started (ok). Else -5.
  2. write_dmp_mem(**0x00**, blob[0x3C:0x3B4], 0x378).
  3. **write_reg8(0x0D, 4)**  (inv_write_reg8: dl=0x0D, r8b=4).
  4. wait_dmp_idle.
After this, 0x0E has bit 0x08 set (and bit 0x40 clear) = serviceable.

### inv_fp_open_session handshake (FUN_1800ba4fc) — SOLVED (trigger + response pinned from asm)
Args (sensor_ctx, SID ptr, out[16]). Sequence:
  1. wait_dmp_idle (FUN_1800ba89c): poll reg 0x0E until (v&5)!=1; require (v&6)==2. Caller also
     requires (v & 0x08) set and (v & 0x40) clear, else errors -5/-6.
  2. write_dmp_mem(**0x3D0**, SID, 8) (FUN_1800ba43c): serial_write(0x08, 0x3D0 LE32); serial_write(0x0C, SID).
  3. **trigger = write_reg8(0x0D, 8)** (FUN_1800ba9b0; asm: dl=0x0D, r8b=8). Same trigger register as
     inv_fp_start, value 8 instead of 4.
  4. wait_dmp_idle; then FUN_1800ba960(100): poll the ready flag ≤100 ms = wait until
     (read_reg8(**0x39**) & 4) == 0 (FUN_1800ba15c reads reg 0x39, tests bit 2).
  5. **response = read_reg(0x87, 16)** (FUN_1800ba720 → serial_read(0x87, 16), asm: dl=0x87). This is a
     direct sensor-register read, NOT a read_dmp_mem of 0x3D0 — which is why the old DMP-RAM sweep only
     ever echoed the SID back.
Then iid_VerifySessionOpen checks the response against the oracle and, on match, caches
cmac_key/ctr_key and the active SID. Probe: `rts5812_probe.py --warm-dmp --open-session` arms the
responder (inv_fp_start) and runs the exact handshake, checking the reply against the oracle.

NOTE for a Linux port: the blob already carries a valid (SID, response) pair, and capture only needs
SID (from the frame header) + K, so **decrypt works without performing a fresh handshake**. The
handshake is only required to negotiate a *new* SID (e.g. after the sensor loses session state), and
a fresh handshake also requires replaying blob[0x3C:] via inv_fp_start first.

## Frame crypto — SOLVED (iid_VerifyAndDecrypt 0x1800c1140)
Frame = first 0x41A0 of the 0x4200 getImageData transfer, laid out:
    [0x0000:0x000C] 12-B header = SID(8) || 00 00 00 00   (must match DAT_1801bc820/828 = SID,0)
    [0x000C:0x0010] 4-B big-endian monotonic message counter (replay; 0xFFFFFFFF rejected)
    [0x0010:0x0020] 16-B AES-256-CBC IV
    [0x0020:0x4190] 0x4170-B AES-256-CBC ciphertext (the image), key = ctr_key (KDF mode 1)
    [0x4190:0x41A0] 16-B AES-256-CMAC tag over bytes [0x0000:0x4190], cmac_key
Plaintext image (saveImage2PGM 0x1800b8ee0): **135 × 62 (0x20B2 px) 8-bit grey at plaintext off 0x20B4**.

### CORRECTION (2026-10-19): body cipher is AES-256-CBC, not CTR — HARDWARE-VERIFIED
An earlier revision read FUN_1800c2a80 as AES-CTR. Decoding a real captured frame
(a captured frame.bin + frame.bin.blob) settles it as **CBC**, confirmed two ways:
  1. Oracle: cmac_key/ctr_key derived from K=blob[0x1C:0x3C] + SID=frame[0:8] via the KDF
     below reproduce the frame's AES-256-CMAC tag EXACTLY (27b0c299…a5d5) — the KDF and keys
     are therefore provably correct. CTR decryption of the body then yields noise (byte
     histogram ~flat, 0.13), while AES-256-CBC with IV=frame[0x10:0x20] yields a clean
     135×62 fingerprint (histogram concentration 0.997) landing exactly at plaintext 0x20B4.
  2. Source: FUN_1800c2a80 is a CBC-decrypt loop — per 16-B block it calls the AES single-block
     *decrypt* (FUN_1800c2420), XORs the result with the previous ciphertext block (chaining
     value seeded from the IV at DAT_1801bc830), then copies the current ciphertext block in as
     the next chaining value. That is CBC; CTR would encrypt a counter and keep no cipher chain.
Net: the whole frame path (KDF → CMAC verify → CBC decrypt → 135×62 PGM) now runs offline and
is verified against real hardware. Reference impl: rts5812_decode.py.

## Implication for a Linux port
Already-paired device → use the *open* path (no enrol): retrieve blob → K = blob[0x1C:0x3C] → use
the SID from the frame header (or negotiate a new one via inv_fp_open_session) → derive
cmac_key/ctr_key → setSensorMode(1) → getImageData → CMAC-verify, **CBC-decrypt** → 135×62 PGM.
This whole path is hardware-verified today (offline decode of a real frame; blob self-check of the
KDF). The fresh-SID handshake is now also fully mapped from the DLL: inv_fp_start arms the responder
(blob[0x3C:] → DMP 0, w(0x0D,4)) and inv_fp_open_session runs trigger w(0x0D,8) → ready-poll on reg
0x39 bit 2 → response read_reg(0x87,16). These were the last two vtable-hidden registers; they are
needed only to negotiate a *fresh* SID, not for capture. Pending: a hardware run confirming the oracle
matches the reg-0x87 reply. Userspace tools: rts5812_probe.py
(--capture, --warm-dmp, --open-session[--sweep]) and rts5812_decode.py; C reference in
libfprint-rts5812/.

