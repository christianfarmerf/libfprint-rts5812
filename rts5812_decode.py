#!/usr/bin/env python3
"""Offline decoder for an RTS5812/TCFS2000 encrypted image frame.

Takes a raw frame captured by `rts5812_probe.py --capture` plus the per-device
key blob, derives the session keys the way the Windows driver does
(iid_VerifySessionOpen 0x1800c13e0 / KDF 0x1800c1c00), verifies the AES-CMAC
tag, decrypts the image (iid_VerifyAndDecrypt 0x1800c1140), and writes a PGM.

This is fully offline: the capture carries the 8-byte session id in its header,
and the key blob carries the 32-byte master key, so no device round-trip is
needed. The CMAC tag is a definitive oracle — if it verifies, the derived keys
are provably correct.

Frame layout (first 0x41A0 bytes of the 0x4200 transfer), from PROTOCOL.md:
    [0x0000 .. 0x0007]  8-byte session id (SID)
    [0x0008 .. 0x000B]  4 zero bytes
    [0x000C .. 0x000F]  4-byte big-endian message counter (replay protection)
    [0x0010 .. 0x001F]  16-byte AES-CBC IV
    [0x0020 .. 0x418F]  0x4170 bytes AES-256-CBC ciphertext (the image)
    [0x4190 .. 0x419F]  16-byte AES-256-CMAC tag over bytes [0x0000 .. 0x418F]

Crypto (verified byte-accurate against real hardware — see PROTOCOL.md):
    master key K   = keyblob[0x1C:0x3C]            (32 bytes, AES-256)
    SID            = frame[0x00:0x08]
    cmac_key       = KDF(mode=2, SID, K)           (32 bytes)
    ctr_key        = KDF(mode=1, SID, K)           (32 bytes; names the body key)
    KDF(mode) = AES256_CMAC_K(block0) || AES256_CMAC_K(block1), where
        block(i) = 00 i mode 00 | SID[0:8] | 00 00 01 00     (16 bytes)
    integrity: AES-256-CMAC over frame[0x0000:0x4190] with cmac_key
    body:      AES-256-CBC decrypt of frame[0x0020:0x4190], IV = frame[0x10:0x20]

NOTE: the body cipher is AES-CBC, not AES-CTR. PROTOCOL.md originally read
FUN_1800c2a80 as CTR; decrypting a real captured frame proves it is CBC (the
CMAC verifies and only CBC yields an image). CBC and CTR share AES's round core
and key schedule, which is why the decompile was ambiguous.

Plaintext image geometry (saveImage2PGM 0x1800b8ee0):
    135 x 62 (= 8370 px) 8-bit grayscale, at plaintext offset 0x20B4.

Requires:  pip install pycryptodome
Usage:
    python3 rts5812_decode.py FRAME.bin --blob FRAME.bin.blob [--out image.pgm]
    python3 rts5812_decode.py FRAME.bin --key-hex <64-hex master key K>
"""

import argparse
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC
except ImportError:
    sys.exit("error: pycryptodome is required -> pip install pycryptodome")

FRAME_LEN = 0x41A0
CT_OFF, CT_END = 0x20, 0x4190
IV_OFF = 0x10
CMAC_OFF = 0x4190
MASTER_KEY_OFF = 0x1C                       # offset of K inside the TCFS key blob
IMG_OFF, IMG_W, IMG_H = 0x20B4, 135, 62


def aes_cmac(key, data):
    return CMAC.new(key, ciphermod=AES).update(data).digest()


def kdf(master_key, sid, mode):
    """SP800-108-style key derivation (FUN_1800c1c00).

    out = AES256_CMAC_K(block0) || AES256_CMAC_K(block1)
    block(i) = 00 | i | mode | 00 | SID[0:8] | 00 00 | 01 | 00   (16 bytes)
    """
    out = b""
    for i in (0, 1):
        block = bytes([0x00, i, mode, 0x00]) + sid + b"\x00\x00\x01\x00"
        out += aes_cmac(master_key, block)
    return out


def write_pgm(path, pixels, w, h):
    with open(path, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (w, h))
        f.write(pixels[: w * h])


def main():
    ap = argparse.ArgumentParser(description="Decode an RTS5812 encrypted image frame")
    ap.add_argument("frame", help="raw frame file from --capture (0x4200 or 0x41A0 bytes)")
    ap.add_argument("--blob", help="per-device key blob (FRAME.bin.blob); K = blob[0x1C:0x3C]")
    ap.add_argument("--key-hex", help="master key K as 64 hex chars (overrides --blob)")
    ap.add_argument("--out", default="rts5812.pgm", help="output PGM path (default rts5812.pgm)")
    args = ap.parse_args()

    frame = open(args.frame, "rb").read()
    if len(frame) < FRAME_LEN:
        sys.exit("error: frame is %d bytes, need at least 0x%X" % (len(frame), FRAME_LEN))
    f = frame[:FRAME_LEN]

    if args.key_hex:
        K = bytes.fromhex(args.key_hex.replace(" ", ""))
    elif args.blob:
        blob = open(args.blob, "rb").read()
        K = blob[MASTER_KEY_OFF:MASTER_KEY_OFF + 32]
    else:
        blobpath = args.frame + ".blob"
        try:
            blob = open(blobpath, "rb").read()
        except OSError:
            sys.exit("error: need the key blob; pass --blob FRAME.bin.blob or --key-hex")
        K = blob[MASTER_KEY_OFF:MASTER_KEY_OFF + 32]
    if len(K) != 32:
        sys.exit("error: master key K must be 32 bytes, got %d" % len(K))

    sid = f[0:8]
    iv = f[IV_OFF:IV_OFF + 16]
    ct = f[CT_OFF:CT_END]
    tag = f[CMAC_OFF:CMAC_OFF + 16]

    cmac_key = kdf(K, sid, 2)
    ctr_key = kdf(K, sid, 1)

    print("K        %s" % K.hex())
    print("SID      %s   counter %s   IV %s" % (sid.hex(), f[12:16].hex(), iv.hex()))
    print("cmac_key %s" % cmac_key.hex())
    print("ctr_key  %s" % ctr_key.hex())

    calc = aes_cmac(cmac_key, f[:CMAC_OFF])
    if calc == tag:
        print("CMAC     %s  VERIFIED (keys are correct)" % calc.hex())
    else:
        print("CMAC     %s  MISMATCH (expected %s)" % (calc.hex(), tag.hex()))
        print("  the derived keys do not match this frame; check the blob / SID.")

    pt = AES.new(ctr_key, AES.MODE_CBC, iv).decrypt(ct)
    img = pt[IMG_OFF:IMG_OFF + IMG_W * IMG_H]
    write_pgm(args.out, img, IMG_W, IMG_H)
    print("wrote %dx%d PGM -> %s" % (IMG_W, IMG_H, args.out))
    if calc != tag:
        sys.exit(2)


if __name__ == "__main__":
    main()
