#!/usr/bin/env python3
"""Userspace probe / skeleton driver for the Realtek RTS5812 fingerprint bridge
(USB 0bda:5812) with a TDK/InvenSense TCFS2000 sensor.

This implements the bulk command protocol reverse-engineered from the Windows
driver RtsWBDI.dll (see PROTOCOL.md). It is a *userspace* tool using
libusb (via pyusb) so it can be tested without building a kernel module.

It is READ-ONLY and safe by default: it opens the device, finds the endpoints,
and runs a few status/identity reads. It does NOT flash firmware and does NOT
write sensor configuration unless you pass an explicit opt-in flag.

Test on a Linux machine/live-USB where the device is free:
    sudo python3 rts5812_probe.py
On Windows the device is owned by the Windows Hello driver; using it here would
require rebinding to WinUSB (Zadig) and would disable Windows Hello, so prefer
Linux for testing.

Requires:  pip install pyusb   (+ libusb-1.0 present on the system)
"""

import argparse
import os
import sys
import time

import usb.core
import usb.util

VID, PID = 0x0BDA, 0x5812

# --- bridge command opcodes (byte 1 of the 8-byte header) -------------------
OP_READ_REG = 0xE1   # read  <len> bytes from sensor register <reg>
OP_WRITE_REG = 0x61  # write <len> bytes to   sensor register <reg>
OP_IMG_DATA = 0x62   # read  <len> bytes of image data
OP_IMG_STATUS = 0x63 # read  1 status byte (1 == frame ready)
OP_SET_MODE = 0xE4   # write 1 byte sensor mode
OP_KEY_STORE = 0x68  # write session key to bridge flash
OP_KEY_FETCH = 0xE8  # read  session key from bridge flash

STATUS_LEN = 5       # every command ends with a 5-byte status; byte 0 == 0 is OK
IMAGE_XFER_LEN = 0x4200  # bytes requested by readImage(); frame proper is the first 0x41A0
FRAME_LEN = 0x41A0       # encrypted frame: 12B header | 4B ctr | 16B IV | 0x4170 CT | 16B CMAC
KEY_LEN = 32             # bytes of the device-key blob the original probe dumped
BLOB_LEN = 0x3B4         # full device-key blob ("TCFS"...) retrieveDeviceKey reads
MASTER_KEY_OFF = 0x1C    # 32-byte AES-256 master key K within the blob (obj+0x24 - obj+0x8)

# --- encrypted-frame layout + plaintext image geometry (iid_VerifyAndDecrypt,
#     saveImage2PGM 0x1800b8ee0; see PROTOCOL.md / rts5812_decode.py) ------
IV_OFF = 0x10            # 16-byte AES-256-CBC IV
CT_OFF, CT_END = 0x20, 0x4190   # 0x4170-byte ciphertext body
CMAC_OFF = 0x4190        # 16-byte AES-256-CMAC tag over frame[0:0x4190]
IMG_OFF, IMG_W, IMG_H = 0x20B4, 135, 62   # 135x62 8-bit grey at plaintext 0x20B4

# --- DMP / sensor register map (from PROTOCOL.md) ---------------------------
DMP_ADDR_REG = 0x08      # serial_write(0x08, addr LE32) sets the DMP mem pointer
DMP_WRITE_REG = 0x0C     # serial_write(0x0C, data) streams into DMP mem
DMP_READ_REG = 0x8C      # serial_read(0x8C, n) streams out of DMP mem
REG_DMP_STATUS = 0x0E    # wait_dmp_idle polls this; ok iff (v & 6) == 2
SID_DMP_ADDR = 0x3D0     # inv_fp_open_session writes the 8-byte SID here
SID_LEN = 8
SESSION_RESP_LEN = 16    # sensor returns a 16-byte AES-256-CMAC over SID||0^8

# --- session handshake registers (recovered from the inv_fp_start /
#     inv_fp_open_session disassembly; Ghidra dropped these immediates, so they
#     were pinned from the raw asm of RtsWBDI.dll 0x1800ba820 / 0x1800ba4fc) ----
REG_SESSION_TRIGGER = 0x0D   # inv_write_reg8(0x0D, v): v=4 arms (inv_fp_start),
                             # v=8 opens a session (inv_fp_open_session step 3)
SESSION_START_VAL = 0x04
SESSION_OPEN_VAL = 0x08
SESSION_RESP_REG = 0x87      # inv_fp_open_session reads the 16-byte reply from HERE
                             # via serial_read(0x87, 16) (FUN_1800ba720) -- a direct
                             # register read, NOT a read_dmp_mem of 0x3D0
REG_DMP_READY = 0x39         # ready-poll (FUN_1800ba960): wait until (r(0x39) & 4) == 0
START_BLOB_OFF = 0x3C        # blob[0x3C:0x3B4] = the 0x378-byte per-device session-
START_BLOB_LEN = 0x378       # start material inv_fp_start replays into the DMP
START_DMP_ADDR = 0x00        # inv_fp_start writes that material to DMP address 0


# --- session-open crypto (lazy: only needed for --open-session) -------------
def _load_crypto():
    try:
        from Crypto.Cipher import AES
        from Crypto.Hash import CMAC
    except ImportError:
        raise Rts5812Error("pycryptodome required for --open-session: pip install pycryptodome")
    return AES, CMAC


def aes_cmac(key, data):
    AES, CMAC = _load_crypto()
    return CMAC.new(key, ciphermod=AES).update(data).digest()


def kdf(master_key, sid, mode):
    """Session KDF (FUN_1800c1c00): out = CMAC_K(blk0) || CMAC_K(blk1),
    blk(i) = 00 i mode 00 | SID[0:8] | 00 00 01 00."""
    out = b""
    for i in (0, 1):
        out += aes_cmac(master_key, bytes([0, i, mode, 0]) + sid + b"\x00\x00\x01\x00")
    return out


def session_oracle(master_key, sid):
    """Expected sensor response = AES256_CMAC_{cmac_key}(SID || 0^8), the value
    iid_VerifySessionOpen (0x1800c13e0) checks inv_fp_open_session's reply against."""
    cmac_key = kdf(master_key, sid, 2)
    return aes_cmac(cmac_key, sid + b"\x00" * (16 - len(sid)))


def decode_frame(frame, master_key):
    """Verify + decrypt a captured frame the way iid_VerifyAndDecrypt does, using
    the frame's OWN SID (frame[0:8]) + the device master key K. The AES-256-CMAC
    tag is the definitive oracle: if it verifies, the derived keys and the
    plaintext image are provably correct. Returns a dict (keys, cmac_ok, image).
    Mirrors rts5812_decode.py so the live capture is self-checking."""
    AES, _ = _load_crypto()
    f = frame[:FRAME_LEN]
    sid = f[0:8]
    iv = f[IV_OFF:IV_OFF + 16]
    ct = f[CT_OFF:CT_END]
    tag = f[CMAC_OFF:CMAC_OFF + 16]
    cmac_key = kdf(master_key, sid, 2)
    ctr_key = kdf(master_key, sid, 1)        # body key (KDF mode 1); name kept for parity
    calc = aes_cmac(cmac_key, f[:CMAC_OFF])
    pt = AES.new(ctr_key, AES.MODE_CBC, iv).decrypt(ct)
    return {
        "sid": sid, "counter_be": f[0x0C:0x10], "iv": iv,
        "cmac_key": cmac_key, "ctr_key": ctr_key,
        "cmac_ok": calc == tag, "cmac_calc": calc, "cmac_tag": tag,
        "image": pt[IMG_OFF:IMG_OFF + IMG_W * IMG_H],
    }


def image_stats(img):
    """Tell a real (finger-present) frame from a blank platen or a mis-decrypt.
    `concentration` = the largest share of pixels in any 32-wide intensity band:
    ~0.13 for uniform noise, ~0.99 when a dominant background is present (matches
    PROTOCOL.md's 0.13 / 0.997). `stddev` is near 0 for a blank platen and rises
    once ridges are actually imaged. The CMAC remains the correctness oracle; this
    only gauges whether a finger was really on the sensor."""
    n = len(img)
    if not n:
        return {"n": 0, "min": 0, "max": 0, "mean": 0.0, "stddev": 0.0, "concentration": 0.0}
    hist = [0] * 256
    for b in img:
        hist[b] += 1
    window = sum(hist[:32])
    best = window
    for v in range(1, 256 - 32 + 1):
        window += hist[v + 31] - hist[v - 1]
        best = max(best, window)
    mean = sum(i * c for i, c in enumerate(hist)) / n
    var = sum(c * (i - mean) ** 2 for i, c in enumerate(hist)) / n
    return {"n": n, "min": min(img), "max": max(img), "mean": mean,
            "stddev": var ** 0.5, "concentration": best / n}


def write_pgm(path, pixels, w, h):
    with open(path, "wb") as fh:
        fh.write(b"P5\n%d %d\n255\n" % (w, h))
        fh.write(bytes(pixels[: w * h]))


class Rts5812Error(Exception):
    pass


# DMP-memory transfer chunk. The driver bounds every serial_write(0x0C)/
# serial_read(0x8C) to dev->max_xfer-1 bytes (inv_fp_write_dmp_mem, PROTOCOL.md).
# max_xfer is never a literal in the decompile, but the hardware pins it: both
# 0x4000 and 0x3FFF STALL the bulk-OUT pipe on the very first 0x0C chunk (libusb
# "Pipe error", errno 32), while every <=4-byte register write goes through. So
# the earlier "exact-multiple-of-512 / missing short packet" theory was wrong --
# 0x3FFF is not a 512-multiple and still stalls. The bridge's writeReg handler
# just will not accept a payload anywhere near 16 KB. The principled value is
# max_xfer-1 with max_xfer == the bulk endpoint's max packet (512 on high speed),
# i.e. the driver sends at most one packet of sensor data per writeReg. 0x1FF
# (511 bytes) is that bound; the 0x7CA8-byte firmware then uploads in ~63 chunks,
# which is still only milliseconds over USB. Raise --dmp-chunk later to speed it
# up once a run proves a larger size is accepted.
DEFAULT_DMP_CHUNK = 0x1FF


class Rts5812:
    def __init__(self, dev, timeout_ms=4000, verbose=True, dmp_chunk=DEFAULT_DMP_CHUNK):
        self.dev = dev
        self.timeout = timeout_ms
        self.verbose = verbose
        self.DMP_CHUNK = dmp_chunk
        self.ep_out = self.ep_in = None
        self.ep_int = []

    # -- setup ---------------------------------------------------------------
    def open(self):
        dev = self.dev
        # On Linux, drop any kernel driver bound to interface 0 so we can claim it.
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
                self._log("detached kernel driver from interface 0")
        except (NotImplementedError, usb.core.USBError):
            pass
        dev.set_configuration()
        cfg = dev.get_active_configuration()
        intf = cfg[(0, 0)]
        usb.util.claim_interface(dev, intf.bInterfaceNumber)
        for ep in intf:
            attr = ep.bmAttributes & 0x3
            direction = usb.util.endpoint_direction(ep.bEndpointAddress)
            if attr == usb.util.ENDPOINT_TYPE_BULK:
                if direction == usb.util.ENDPOINT_IN:
                    self.ep_in = ep.bEndpointAddress
                else:
                    self.ep_out = ep.bEndpointAddress
            elif attr == usb.util.ENDPOINT_TYPE_INTR and direction == usb.util.ENDPOINT_IN:
                self.ep_int.append(ep.bEndpointAddress)
        self._log("endpoints: bulk_out=%s bulk_in=%s interrupt_in=%s" % (
            _hx(self.ep_out), _hx(self.ep_in), [_hx(e) for e in self.ep_int]))
        if self.ep_in is None or self.ep_out is None:
            raise Rts5812Error("could not find both bulk endpoints on interface 0")

    def close(self):
        usb.util.dispose_resources(self.dev)

    # -- core command protocol ----------------------------------------------
    def _header(self, op, reg, length):
        return bytes([0xF0, op, 0x00, 0x00, reg & 0xFF, 0x00, length & 0xFF, (length >> 8) & 0xFF])

    def _check_status(self, op):
        status = self.dev.read(self.ep_in, STATUS_LEN, self.timeout)
        if len(status) != STATUS_LEN:
            raise Rts5812Error("op %#x: short status (%d bytes)" % (op, len(status)))
        if status[0] != 0:
            raise Rts5812Error("op %#x: device status error 0x%02x" % (op, status[0]))
        return bytes(status)

    def command(self, op, reg=0, data_out=None, read_len=0):
        """One full bridge command: header -> [out data] | [in data] -> 5-byte status."""
        length = len(data_out) if data_out is not None else read_len
        try:
            self.dev.write(self.ep_out, self._header(op, reg, length), self.timeout)
            payload = b""
            if data_out is not None:
                self.dev.write(self.ep_out, bytes(data_out), self.timeout)
            elif read_len:
                payload = bytes(self.dev.read(self.ep_in, read_len, self.timeout))
        except usb.core.USBError as e:
            # A STALL (errno 32, "Pipe error") leaves the endpoint halted; clear it
            # so the device stays usable instead of needing a replug, then report.
            self._clear_stall()
            raise Rts5812Error(
                "op %#x (reg=%#x len=%d): USB transfer failed: %s"
                % (op, reg, length, e))
        self._check_status(op)
        return payload

    def _clear_stall(self):
        for ep in (self.ep_out, self.ep_in):
            if ep is not None:
                try:
                    self.dev.clear_halt(ep)
                except usb.core.USBError:
                    pass

    # -- convenience wrappers (match RtsWBDI.dll names) ----------------------
    def read_reg(self, reg, n):
        return self.command(OP_READ_REG, reg=reg, read_len=n)

    def write_reg(self, reg, data):
        self.command(OP_WRITE_REG, reg=reg, data_out=data)

    def image_status(self):
        # getImageStatus: read 1 byte; 1 means a frame is ready.
        return self.command(OP_IMG_STATUS, read_len=1)[0]

    def fetch_session_key(self, n=32):
        return self.command(OP_KEY_FETCH, read_len=n)

    def set_sensor_mode(self, mode):
        self.command(OP_SET_MODE, data_out=bytes([mode & 0xFF]))

    def get_image_data(self, length=IMAGE_XFER_LEN):
        # getImageData (F0 62): read <length> bytes of image frame, then 5-byte status.
        # The Windows driver requests 0x4200; only the first 0x41A0 is the crypto frame.
        return self.command(OP_IMG_DATA, read_len=length)

    def read_image(self, length=IMAGE_XFER_LEN):
        # Mirror SerialDeviceSLWINUSB::readImage: getImageStatus(); if 1 -> getImageData().
        if self.image_status() != 1:
            return None
        return self.get_image_data(length)

    # -- sensor register / DMP helpers (inv_fp layer) ------------------------
    def read_reg8(self, reg):
        # read_reg8(r) = serial_read(r | 0x80, 1)  (0x1800ba7a8)
        return self.read_reg(reg | 0x80, 1)[0]

    def write_reg8(self, reg, val):
        # write_reg8(r, v) = serial_write(r, [v], 1)  (0x1800ba9b0)
        self.write_reg(reg, bytes([val & 0xFF]))

    def write_dmp_mem(self, addr, data):
        # write_dmp_mem (0x1800ba43c): set the DMP pointer once, then stream the
        # bytes; the pointer auto-advances across successive 0x0C writes, so large
        # buffers (e.g. the 0x7CA8-byte DMP firmware) are chunked.
        self.write_reg(DMP_ADDR_REG, addr.to_bytes(4, "little"))
        data = bytes(data)
        for off in range(0, max(len(data), 1), self.DMP_CHUNK):
            self.write_reg(DMP_WRITE_REG, data[off:off + self.DMP_CHUNK])

    def read_dmp_mem(self, addr, n):
        # read_dmp_mem (0x1800ba37c): set the DMP pointer once, then stream n bytes
        # out; the pointer auto-advances across successive 0x8C reads, so large
        # reads are chunked.
        self.write_reg(DMP_ADDR_REG, addr.to_bytes(4, "little"))
        out = b""
        while len(out) < n:
            out += self.read_reg(DMP_READ_REG, min(self.DMP_CHUNK, n - len(out)))
        return out

    def wait_dmp_idle(self, tries=100):
        # wait_dmp_idle (0x1800ba89c): poll reg 0x0E; ok iff (v & 6) == 2.
        v = 0
        for _ in range(tries):
            v = self.read_reg8(REG_DMP_STATUS)
            if (v & 5) != 1:
                break
            time.sleep(0.001)
        if v & 1:
            raise Rts5812Error("wait_dmp_idle: DMP busy (0x0E=0x%02x)" % v)
        if (v & 6) != 2:
            raise Rts5812Error("wait_dmp_idle: not idle (0x0E=0x%02x)" % v)
        return v

    # -- sensor bring-up primitives (setupDevice layer, PROTOCOL.md) ---------
    def hardware_reset(self):
        # hardware_reset (0x1800ba118): w(0x3A,0x02); 2ms; w(0x04,0x3F); 1ms.
        self.write_reg8(0x3A, 0x02)
        time.sleep(0.002)
        self.write_reg8(0x04, 0x3F)
        time.sleep(0.001)

    def lp_mode_set(self, enable):
        # lp_mode_set (0x1800ba2fc): w(0x01, en?1:0); when waking, wait for r(0x39) bit1.
        self.write_reg8(0x01, 1 if enable else 0)
        if not enable:
            time.sleep(0.005)
            for _ in range(10):
                if self.read_reg8(0x39) & 0x02:
                    return
                time.sleep(0.001)
            raise Rts5812Error("lp_mode_set(0): r(0x39) bit1 never set")

    def dmp_halt(self, tries=1000):
        # dmp_halt (0x1800ba0c8): loop until r(0x39)&4; kick with w(0x04,0x20).
        # Original has no timeout; cap it here for safety.
        for _ in range(tries):
            if self.read_reg8(0x39) & 0x04:
                return
            self.write_reg8(0x04, 0x20)
        raise Rts5812Error("dmp_halt: r(0x39) bit2 never set")

    def wait_irq(self, tries=500):
        # wait_irq (0x1800ba908): poll r(0x03)==1, 1ms apart, up to <tries>.
        for _ in range(tries):
            if self.read_reg8(0x03) == 1:
                return
            time.sleep(0.001)
        raise Rts5812Error("wait_irq: r(0x03) never == 1")

    def dmp_start(self):
        # dmp_start (0x1800b9ff8): fixed register program that starts the DMP core.
        for reg, val in ((0x1B, 0x60), (0x10, 0x00), (0x11, 0x00), (0x12, 0x01),
                         (0x14, 0x04), (0x15, 0x00), (0x16, 0x01), (0x18, 0x08),
                         (0x19, 0x00), (0x1A, 0x01), (0x7C, 0x01)):
            self.write_reg8(reg, val)

    def load_dmp_firmware(self, fw):
        # load_dmp_firmware (0x1800ba190): w(0x04,0x01); upload fw to DMP 0x10000;
        # read back + verify; dmp_start; w(0x3E,0x04).
        self.write_reg8(0x04, 0x01)
        self.write_dmp_mem(0x10000, fw)
        back = bytes(self.read_dmp_mem(0x10000, len(fw)))
        if back != fw:
            nbad = sum(1 for a, b in zip(back, fw) if a != b) + abs(len(back) - len(fw))
            self._log("WARNING: firmware read-back mismatch (%d/%d bytes differ)"
                      % (nbad, len(fw)))
        else:
            self._log("firmware upload verified (%d bytes)" % len(fw))
        self.dmp_start()
        self.write_reg8(0x3E, 0x04)

    def bypass_gain_comp_enable(self, enable):
        # bypass_gain_comp_enable (0x1800b9d64): dmp[0x16AAF] = en ? 3 : 0.
        self.write_dmp_mem(0x16AAF, bytes([3 if enable else 0]))

    def apply_custom_generator(self):
        # applyCustomGenerator (0x1800b8ac8): dmp[0x16E18] = 0x0000005A (LE32).
        # setupDevice runs this immediately before change_dmp_mode(5).
        self.write_dmp_mem(0x16E18, bytes([0x5A, 0x00, 0x00, 0x00]))

    def change_mode_simple(self, mode):
        # change_mode_simple (0x1800b9d8c): halt; idle; w(0x1D,mode); 5/12/20 clear 0x55.
        self.dmp_halt()
        self.wait_dmp_idle()
        self.write_reg8(0x1D, mode)
        if mode in (5, 12, 20):
            self.write_reg8(0x55, 0)

    def change_dmp_mode_with_completion(self, mode):
        # change_dmp_mode_with_completion (0x1800b9df0).
        if mode in (5, 12, 20):
            self.write_reg8(0x1D, mode)
            self.wait_irq(500)
            if self.read_reg8(0x55) == 1:
                self.dmp_halt()
                self.write_reg8(0x55, 0)
                self.wait_irq(500)
            self.wait_dmp_idle()
        else:
            self.change_mode_simple(mode)
            self.wait_irq(500)

    # -- security-session responder (the step that actually arms bit 0x08) ----
    def wait_session_ready(self, tries=100):
        # inv_fp_open_session step 4.5 (FUN_1800ba960 -> FUN_1800ba15c): poll reg
        # 0x39 and wait until bit 2 clears, i.e. (read_reg8(0x39) & 4) == 0, <=100ms.
        for _ in range(tries):
            if (self.read_reg8(REG_DMP_READY) & 0x04) == 0:
                return
            time.sleep(0.001)
        raise Rts5812Error("wait_session_ready: r(0x39) bit2 never cleared")

    def start_session(self, start_material):
        # inv_fp_start (0x1800ba820), the securitySessionStart step that arms the
        # on-chip session responder. This -- not change_dmp_mode -- is what flips
        # reg 0x0E bit 0x08. Precondition from the asm: wait_dmp_idle, then reg 0x0E
        # bit 0x20 must be set (the state modes 1/14/5 leave the DMP in; a bare
        # (0x0E & 0x0A)==0x0A means the responder is already armed). Then write the
        # 0x378-byte per-device start material (blob[0x3C:0x3B4]) to DMP address 0
        # and poke write_reg8(0x0D, 4).
        v = self.wait_dmp_idle()
        if not (v & 0x20):
            if (v & 0x0A) == 0x0A:
                return v  # already started / responder already armed
            raise Rts5812Error(
                "start_session: 0x0E=0x%02x not ready to start (bit0x20 clear)" % v)
        if len(start_material) != START_BLOB_LEN:
            raise Rts5812Error("start_session: start material must be %d bytes (got %d)"
                               % (START_BLOB_LEN, len(start_material)))
        self.write_dmp_mem(START_DMP_ADDR, start_material)
        self.write_reg8(REG_SESSION_TRIGGER, SESSION_START_VAL)
        return self.wait_dmp_idle()

    def open_session(self, sid):
        # inv_fp_open_session (0x1800ba4fc). Returns the 16-byte sensor response,
        # which iid_VerifySessionOpen checks against AES256_CMAC_{cmac_key}(SID||0^8).
        # Requires the responder armed: 0x0E bit 0x08 set and bit 0x40 clear.
        v = self.wait_dmp_idle()
        if not (v & 0x08):
            raise Rts5812Error(
                "open_session: responder not armed (0x0E=0x%02x bit0x08 clear; "
                "run start_session first)" % v)
        if v & 0x40:
            raise Rts5812Error("open_session: 0x0E=0x%02x bit0x40 set" % v)
        self.write_dmp_mem(SID_DMP_ADDR, sid)          # SID -> DMP 0x3D0
        self.write_reg8(REG_SESSION_TRIGGER, SESSION_OPEN_VAL)  # trigger
        self.wait_dmp_idle()
        self.wait_session_ready(100)
        return bytes(self.read_reg(SESSION_RESP_REG, SESSION_RESP_LEN))  # reg 0x87

    def _log(self, msg):
        if self.verbose:
            print("[rts5812]", msg)


def _hx(v):
    return "0x%02x" % v if isinstance(v, int) else str(v)


def find_device():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise Rts5812Error("device %04x:%04x not found (is it plugged in and free?)" % (VID, PID))
    return dev


def main():
    ap = argparse.ArgumentParser(description="RTS5812 fingerprint bridge userspace probe")
    ap.add_argument("--set-mode", action="store_true",
                    help="opt-in: also setSensorMode(1) and poll image status (writes to device)")
    ap.add_argument("--poll", type=int, default=20, help="status poll iterations with --set-mode")
    ap.add_argument("--capture", metavar="PATH",
                    help="opt-in: arm sensor, wait for a finger, then read out one image "
                         "frame and write it to PATH (raw 0x4200 bytes). Also writes "
                         "PATH.key (session key) and PATH.json (parsed frame layout).")
    ap.add_argument("--timeout", type=float, default=15.0,
                    help="seconds to wait for a finger during --capture (default 15)")
    ap.add_argument("--captures", type=int, default=1, metavar="N",
                    help="capture N frames in sequence instead of one (default 1), each a "
                         "distinct press. Files are suffixed _NN before the extension "
                         "(frame_01.bin, frame_02.bin, ...). Lift the finger between presses; "
                         "the probe waits for a clean lift before arming the next. Use this to "
                         "gather same-finger/different-finger frames for an offline match test.")
    ap.add_argument("--label", metavar="TAG", default="",
                    help="tag inserted into multi-capture filenames and metadata (e.g. "
                         "--label index), so a run's frames are self-describing: frame_index01.bin")
    ap.add_argument("--open-session", action="store_true",
                    help="opt-in: pin inv_fp_open_session — write a random SID to DMP 0x3D0 "
                         "and check the sensor's reply against the auth oracle (needs "
                         "pycryptodome)")
    ap.add_argument("--sid", metavar="HEX", help="use this 8-byte SID (hex) instead of random")
    ap.add_argument("--sweep", action="store_true",
                    help="with --open-session: after the real handshake, also dump the old "
                         "DMP-RAM read locations as a diagnostic (the trigger/response are now "
                         "pinned exactly, so this is only for comparison)")
    ap.add_argument("--warm-dmp", action="store_true",
                    help="opt-in: run the setupDevice bring-up (DMP firmware upload + "
                         "change_dmp_mode) to flip reg 0x0E into the serviceable state so "
                         "inv_fp_open_session's responder is armed. Pair with --open-session. "
                         "Writes firmware + sensor mode; replug to reset.")
    ap.add_argument("--fw", metavar="PATH",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "dmp_fw.bin"),
                    help="DMP firmware blob for --warm-dmp (default: dmp_fw.bin next to this script)")
    ap.add_argument("--modes", metavar="LIST", default="1,14,5",
                    help="comma-separated change_dmp_mode_with_completion modes for --warm-dmp "
                         "(default '1,14,5' = the full setupDevice step 9; applyCustomGenerator "
                         "runs automatically just before mode 5). The old default of just '1' "
                         "stopped before the responder arms")
    ap.add_argument("--dmp-chunk", metavar="N", type=lambda s: int(s, 0),
                    default=DEFAULT_DMP_CHUNK,
                    help="bytes per DMP serial_write/serial_read chunk (default 0x1FF = "
                         "max_xfer-1 for a 512-byte bulk packet). Larger values (0x4000, 0x3FFF) "
                         "STALL the OUT pipe on this bridge; raise it only to speed up a run that "
                         "already proved a bigger chunk is accepted")
    ap.add_argument("--reset", action="store_true",
                    help="issue a USB port reset before anything else (re-enumerates the device, "
                         "like a physical replug) to clear an aborted bring-up on a laptop where "
                         "the sensor can't be unplugged. Pair it with --warm-dmp.")
    args = ap.parse_args()

    dev = find_device()
    print("found %04x:%04x" % (VID, PID))
    if args.reset:
        # USBDEVFS_RESET re-enumerates the device = a replug without physical access.
        # reset() can invalidate this handle, so drop it and re-find afterwards.
        try:
            dev.reset()
            print("issued USB port reset; waiting for re-enumeration...")
        except usb.core.USBError as e:
            print("reset note: %s (continuing)" % e)
        usb.util.dispose_resources(dev)
        time.sleep(2)
        dev = find_device()
    fp = Rts5812(dev, dmp_chunk=args.dmp_chunk)
    fp.open()

    # 1) Framing smoke test: getImageStatus is a pure read, safe to issue anytime.
    try:
        st = fp.image_status()
        print("image_status  -> 0x%02x  (command framing OK)" % st)
    except Rts5812Error as e:
        print("image_status  -> FAILED:", e)

    # 2) Identity reads. The TDK sensor WHOAMI should read back 0xAD.
    #    The driver reads sensor registers with the high bit (0x80) set, so try both.
    for reg in (0x00, 0x80):
        try:
            v = fp.read_reg(reg, 1)
            print("read_reg(0x%02x,1) -> %s" % (reg, v.hex()))
        except Rts5812Error as e:
            print("read_reg(0x%02x,1) -> FAILED: %s" % (reg, e))

    # 3) Read back the per-device session key handle (read-only).
    try:
        key = fp.fetch_session_key(32)
        print("session_key(32)  -> %s" % key.hex())
    except Rts5812Error as e:
        print("session_key(32)  -> FAILED:", e)

    if args.set_mode:
        print("\n--set-mode: arming sensor and polling for a finger...")
        fp.set_sensor_mode(1)
        for i in range(args.poll):
            st = fp.image_status()
            print("  poll %2d: image_status = 0x%02x%s" % (i, st, "  <- FRAME READY" if st == 1 else ""))
            if st == 1:
                break
            time.sleep(0.128)

    if args.warm_dmp:
        modes = tuple(int(m, 0) for m in args.modes.split(",") if m.strip())
        warm_dmp(fp, args.fw, modes=modes)

    if args.open_session:
        open_session_probe(fp, sid_hex=args.sid, sweep=args.sweep)

    if args.capture:
        capture_sequence(fp, args.capture, args.timeout, args.captures, args.label)

    fp.close()
    print("done")


def capture_frame(fp, path, timeout_s):
    """Arm the sensor, wait for a finger, read out one image frame, and -- when the
    key blob + pycryptodome are available -- verify and decrypt it inline so the
    live run is self-checking (CMAC VERIFIED + a 135x62 PGM you can look at), not
    just a raw dump to decode afterwards. Returns True on an authentic, imaged frame.

    Capture mirrors the Windows capture thread (0x1800b26b0): setSensorMode(1),
    poll getImageStatus every 128 ms re-arming every 16 iterations, then
    getImageData(0x4200) on FRAME READY. Run it after --warm-dmp --open-session,
    the order setupDevice uses (session opened before the capture thread starts).
    """
    import json

    print("\n--capture: arming sensor; place a finger on the sensor...")
    fp.set_sensor_mode(1)
    deadline = time.time() + timeout_s
    i = 0
    frame = None
    while time.time() < deadline:
        st = fp.image_status()
        if st == 1:
            print("  frame ready after %d polls; reading image..." % i)
            frame = fp.get_image_data(IMAGE_XFER_LEN)
            break
        if i and i % 16 == 0:
            fp.set_sensor_mode(1)  # re-arm, as the driver does every 16 iterations
        i += 1
        time.sleep(0.128)

    if frame is None:
        print("  no finger detected within %.0fs; nothing captured" % timeout_s)
        return False

    with open(path, "wb") as f:
        f.write(frame)
    print("  wrote %d bytes -> %s" % (len(frame), path))

    # The full 0x3B4-byte device-key blob holds the 32-byte AES master key at
    # offset 0x1C; that key + the frame's own SID is all the decrypt needs.
    blob = b""
    for n in (BLOB_LEN, KEY_LEN):
        try:
            blob = fp.fetch_session_key(n)
            with open(path + ".blob", "wb") as f:
                f.write(blob)
            print("  wrote device-key blob (%d bytes) -> %s.blob" % (len(blob), path))
            break
        except Rts5812Error as e:
            print("  blob fetch of %d bytes failed (%s); trying smaller" % (n, e))

    f = frame[:FRAME_LEN]
    meta = {
        "xfer_len": len(frame), "frame_len": FRAME_LEN,
        "header12": f[0x00:0x0C].hex(), "counter_be": f[0x0C:0x10].hex(),
        "iv": f[0x10:0x20].hex(), "ciphertext_len": CT_END - CT_OFF,
        "cmac_tag": f[CMAC_OFF:CMAC_OFF + 16].hex(), "blob": blob.hex(),
    }
    print("  frame: header=%s ctr=%s iv=%s cmac=%s"
          % (meta["header12"], meta["counter_be"], meta["iv"], meta["cmac_tag"]))

    # Inline verify + decrypt: prove the live frame is authentic and look at it.
    ok = False
    if len(blob) >= MASTER_KEY_OFF + 32 and blob[:4] == b"TCFS":
        K = bytes(blob[MASTER_KEY_OFF:MASTER_KEY_OFF + 32])
        try:
            d = decode_frame(frame, K)
            s = image_stats(d["image"])
            meta.update(sid=d["sid"].hex(), cmac_key=d["cmac_key"].hex(),
                        ctr_key=d["ctr_key"].hex(), cmac_ok=d["cmac_ok"],
                        image_stats={k: (round(v, 3) if isinstance(v, float) else v)
                                     for k, v in s.items()})
            pgm = os.path.splitext(path)[0] + ".pgm"
            write_pgm(pgm, d["image"], IMG_W, IMG_H)
            print("  SID=%s  K=%s" % (d["sid"].hex(), K.hex()))
            print("  CMAC %s" % ("VERIFIED (session keys correct, frame authentic)"
                                 if d["cmac_ok"] else
                                 "MISMATCH: calc=%s tag=%s (wrong blob/SID?)"
                                 % (d["cmac_calc"].hex(), d["cmac_tag"].hex())))
            print("  image 135x62 -> %s: min=%d max=%d mean=%.1f stddev=%.1f concentration=%.3f"
                  % (pgm, s["min"], s["max"], s["mean"], s["stddev"], s["concentration"]))
            # stddev is advisory (a real captured finger measured ~6.25, a blank
            # platen ~0); CMAC + the PGM are the real proof. Keep the gate low so a
            # lighter press still reads as imaged.
            if d["cmac_ok"] and s["stddev"] > 3:
                print("  => LIVE CAPTURE OK: authentic frame with an imaged finger"
                      " (open the PGM to confirm ridges).")
                ok = True
            elif d["cmac_ok"]:
                print("  => frame authentic but near-flat (blank platen? press firmly, re-run).")
            else:
                print("  => keys/SID disagree with the frame; check the blob.")
        except Rts5812Error as e:
            print("  inline decode skipped: %s" % e)
            print("  decode offline: python3 rts5812_decode.py %s --blob %s.blob" % (path, path))
    else:
        print("  (no usable TCFS blob; decode offline once you have one: "
              "python3 rts5812_decode.py %s --blob %s.blob)" % (path, path))

    with open(path + ".json", "w") as jf:
        json.dump(meta, jf, indent=2)
    print("  wrote metadata -> %s.json" % path)
    return ok


def wait_finger_lift(fp, timeout_s=6.0):
    """Poll getImageStatus until the finger is off the sensor (status != 1) so the
    next capture is a genuinely separate press, not a re-read of the same contact.
    Returns True once lifted; False if still present after timeout (caller can warn)."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if fp.image_status() != 1:
            time.sleep(0.15)  # small settle so the platen clears before re-arming
            return True
        time.sleep(0.128)
    return False


def _suffix_path(path, label, idx):
    """frame.bin -> frame_index01.bin (label optional): keep the extension, insert the
    tag + zero-padded index before it so a sequence's files sort and self-describe."""
    stem, ext = os.path.splitext(path)
    tag = ("_" + label) if label else ""
    return "%s%s%02d%s" % (stem, tag, idx, ext)


def capture_sequence(fp, base_path, timeout_s, count, label=""):
    """Capture `count` distinct presses in one run for an offline match test. Each
    frame goes through the same verify+decrypt path as a single --capture (its own
    .bin/.blob/.pgm/.json), written to base_path with a _NN suffix. Between presses
    it waits for a finger lift so the frames are independent touches. Returns the
    number of frames that verified+imaged OK."""
    if count <= 1:
        return 1 if capture_frame(fp, base_path, timeout_s) else 0

    print("\n=== multi-capture: %d frames%s ===" % (count, (" (label '%s')" % label) if label else ""))
    print("Lift the finger between presses; re-place when prompted.")
    good = 0
    for i in range(1, count + 1):
        path = _suffix_path(base_path, label, i)
        print("\n--- frame %d of %d -> %s ---" % (i, count, path))
        if capture_frame(fp, path, timeout_s):
            good += 1
        if i < count:
            print("  lift finger for the next press...")
            if not wait_finger_lift(fp):
                print("  (still reading a finger; re-place anyway when ready)")
    print("\n=== multi-capture done: %d/%d frames OK ===" % (good, count))
    return good


def warm_dmp(fp, fw_path, modes=(1, 14, 5)):
    """Run the setupDevice bring-up that arms the session responder.

    The --open-session probe failed before because DMP status reg 0x0E was 0x42
    (bit 0x08 clear, 0x40 set) while inv_fp_open_session requires 0x08 SET and
    0x40 CLEAR; in that cold state the on-chip CMAC responder is inactive and SID
    write/read only round-trips static DMP RAM. This mirrors setupDevice steps 1-9
    (minus trim/OTP and optional tuning) then the securitySessionStart step:
    identity -> wake -> reset -> wake -> DMP firmware upload -> gain-comp off ->
    change_dmp_mode_with_completion(m) for each requested mode -> inv_fp_start.

    setupDevice step 9 is the full sequence change_dmp_mode(1); (14);
    applyCustomGenerator(); (5), so whenever mode 5 is requested here,
    applyCustomGenerator() (dmp[0x16E18] = 0x5A) is issued immediately before it,
    exactly as the driver does. The modes only bring 0x0E to 0x22 (bit 0x20 set);
    the responder is armed by inv_fp_start (start_session below), which the asm
    shows replays blob[0x3C:0x3B4] (the 0x378-byte per-device start material) into
    DMP address 0 and pokes reg 0x0D = 4 -- THAT is the step that flips bit 0x08.
    The earlier default of just '1' never even reached the 0x20 state, and no run
    had run inv_fp_start at all, so bit 0x08 was never set.

    It uploads firmware and changes sensor mode, so it is strictly opt-in. A replug
    resets the sensor if anything goes sideways.
    """
    print("\n--warm-dmp: bringing up the DMP to arm the session responder")
    with open(fw_path, "rb") as f:
        fw = f.read()
    print("  firmware  = %s (%d bytes)" % (fw_path, len(fw)))

    who = fp.read_reg8(0x00)
    print("  whoami    = 0x%02x%s" % (who, "" if who == 0xAD else "  (expected 0xAD!)"))

    def show(tag):
        v = fp.read_reg8(REG_DMP_STATUS)
        serviceable = bool(v & 0x08) and not (v & 0x40)
        print("  0x0E %-9s = 0x%02x  (idle=%d bit0x08=%d bit0x40=%d)%s"
              % (tag, v, int((v & 6) == 2), bool(v & 0x08), bool(v & 0x40),
                 "  <-- SERVICEABLE" if serviceable else ""))
        return v

    show("before")
    fp.lp_mode_set(0)
    fp.hardware_reset()
    fp.lp_mode_set(0)
    fp.load_dmp_firmware(fw)
    try:
        ver = bytes(fp.read_dmp_mem(0x16964, 12))
        print("  fw version= %s" % ver.hex())
    except Rts5812Error as e:
        print("  fw version read failed: %s" % e)
    fp.bypass_gain_comp_enable(0)
    for m in modes:
        try:
            # setupDevice runs applyCustomGenerator() right before mode 5.
            if m == 5:
                fp.apply_custom_generator()
                print("  applyCustomGenerator (dmp[0x16E18]=0x5A) ok")
            fp.change_dmp_mode_with_completion(m)
            print("  change_dmp_mode_with_completion(%d) ok" % m)
        except Rts5812Error as e:
            print("  change_dmp_mode_with_completion(%d) -> %s" % (m, e))
        show("mode%d" % m)

    # The modes leave 0x0E with bit 0x20 set; the responder is armed by inv_fp_start
    # (the securitySessionStart step), which replays the 0x378-byte per-device start
    # material (blob[0x3C:0x3B4]) into DMP address 0 and pokes reg 0x0D = 4. THIS is
    # what flips bit 0x08 -- the mode changes alone never do.
    try:
        blob = fp.fetch_session_key(BLOB_LEN)
        if len(blob) < START_BLOB_OFF + START_BLOB_LEN or blob[:4] != b"TCFS":
            raise Rts5812Error("device-key blob missing/!TCFS (got %d bytes)" % len(blob))
        start_material = bytes(blob[START_BLOB_OFF:START_BLOB_OFF + START_BLOB_LEN])
        fp.start_session(start_material)
        print("  inv_fp_start (blob[0x3c:]-> DMP 0, w(0x0d,4)) ok")
    except Rts5812Error as e:
        print("  inv_fp_start -> %s" % e)
    show("start")

    v = show("after")
    ok = bool(v & 0x08) and not (v & 0x40)
    print("  => responder %s"
          % ("ARMED (0x0E serviceable)" if ok
             else "NOT armed; open-session will still probe but may return static RAM"))
    return ok


def open_session_probe(fp, sid_hex=None, sweep=False):
    """Run inv_fp_open_session (FUN_1800ba4fc) against hardware and check the oracle.

    The trigger register and response location are no longer guessed: they were
    pinned from the raw asm of the DLL (Ghidra had dropped the inv_write_reg8
    immediates). The real handshake is:
      wait_dmp_idle (require 0x0E bit 0x08 set, bit 0x40 clear)
      -> write_dmp_mem(0x3D0, SID, 8)
      -> write_reg8(0x0D, 8)                      (the trigger)
      -> wait_dmp_idle; poll (r(0x39) & 4)==0
      -> read_reg(0x87, 16)                       (the response -- a register read,
                                                    NOT a read_dmp_mem of 0x3D0)
    The reply must equal AES256_CMAC_{KDF(2,SID,K)}(SID||0^8). fp.open_session()
    performs exactly that sequence; here we just drive it and verify.

    This needs the responder armed (reg 0x0E bit 0x08 set), which --warm-dmp does
    via start_session/inv_fp_start. --sweep adds a diagnostic fallback that also
    dumps the old DMP-RAM read locations, to show they only echo the SID.
    """
    print("\n--open-session: running inv_fp_open_session")

    blob = fp.fetch_session_key(BLOB_LEN)
    if len(blob) < MASTER_KEY_OFF + 32 or blob[:4] != b"TCFS":
        raise Rts5812Error("device-key blob missing/!TCFS (got %d bytes)" % len(blob))
    K = bytes(blob[MASTER_KEY_OFF:MASTER_KEY_OFF + 32])
    print("  K = %s" % K.hex())

    try:
        v = fp.read_reg8(REG_DMP_STATUS)
        armed = bool(v & 0x08) and not (v & 0x40)
        print("  DMP status 0x0E = 0x%02x (bit0x08=%d bit0x40=%d)%s"
              % (v, bool(v & 0x08), bool(v & 0x40),
                 "  <-- SERVICEABLE" if armed else "  <-- responder NOT armed"))
    except Rts5812Error as e:
        print("  WARNING: %s (continuing anyway)" % e)

    sid = bytes.fromhex(sid_hex) if sid_hex else os.urandom(SID_LEN)
    if len(sid) != SID_LEN:
        raise Rts5812Error("SID must be %d bytes" % SID_LEN)
    expected = session_oracle(K, sid)
    print("  SID       = %s" % sid.hex())
    print("  oracle    = %s  (expected sensor reply)" % expected.hex())

    # The real handshake: trigger w(0x0D,8), response read_reg(0x87,16).
    try:
        resp = fp.open_session(sid)
        match = resp == expected
        print("  w(0x0d,8) -> read_reg(0x87,16) -> %s %s"
              % (resp.hex(), "<== MATCH" if match else "(no match)"))
        if match:
            cmac_key = kdf(K, sid, 2)
            ctr_key = kdf(K, sid, 1)
            print("\n  SESSION OPEN CONFIRMED")
            print("  trigger   = write_reg8(0x0d, 8)")
            print("  response  = read_reg(0x87, 16)")
            print("  cmac_key  = %s" % cmac_key.hex())
            print("  ctr_key   = %s" % ctr_key.hex())
            return True
    except Rts5812Error as e:
        print("  open_session aborted: %s" % e)

    if sweep:
        # Diagnostic only: show the old DMP-RAM read locations. With the responder
        # armed these should now differ from a bare SID echo; if open_session above
        # already matched we never get here.
        print("  [sweep] DMP-RAM reads near the SID slot (old guess, for comparison):")
        try:
            fp.write_dmp_mem(SID_DMP_ADDR, sid)
            for addr in (SID_DMP_ADDR, SID_DMP_ADDR + 8, SID_DMP_ADDR + 16, SID_DMP_ADDR - 16):
                try:
                    r = bytes(fp.read_dmp_mem(addr, SESSION_RESP_LEN))
                    print("    read_dmp_mem@0x%03x -> %s%s"
                          % (addr, r.hex(), "  <== MATCH" if r == expected else ""))
                except Rts5812Error:
                    continue
        except Rts5812Error as e:
            print("    sweep aborted: %s" % e)

    print("\n  no MATCH.")
    print("  -> if 0x0E was NOT serviceable above, start_session/inv_fp_start did not")
    print("     arm the responder -- read the --warm-dmp '0x0E start' line. If it WAS")
    print("     serviceable, the KDF/oracle disagree with the sensor; capture a Windows")
    print("     USB log of one securitySessionOpen to compare. Replug to reset.")
    return False


if __name__ == "__main__":
    try:
        main()
    except Rts5812Error as e:
        print("error:", e, file=sys.stderr)
        sys.exit(1)
