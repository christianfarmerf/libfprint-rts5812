#!/usr/bin/env python3
"""Offline match-viability harness for RTS5812 captures.

The protocol is solved and live capture works; the one remaining *biometric* risk
before committing to the libfprint C driver is whether these small (135x62), low-
contrast frames carry enough minutiae to enroll and match under libfprint's matcher
(NBIS mindtct + bozorth3). This script answers that from a handful of captured
frames, and tells us whether image normalization is needed first.

What it does, for a set of frames (same finger x several, plus a different finger):
  1. Load each frame -- a .pgm directly, or a raw .bin (+ .bin.blob) it decrypts
     with the proven rts5812_decode path.
  2. Build normalization *variants* of each image and write them out as PGMs so we
     can look at them and feed each to the matcher:
       - raw     : the decrypted image as-is
       - stretch : global 2/98-percentile contrast stretch
       - loceq   : local high-pass + stretch (even illumination, ridges boosted).
                   This one is deliberately simple (box-mean subtract + stretch) so
                   it ports straight into the C driver if it turns out to help.
  3. Report a ridge-structure metric per frame -- orientation *coherence*, which is
     high when oriented ridge flow is present and low on a flat/blank platen,
     independent of raw contrast (a better "is there a finger" signal than stddev).
  4. If NBIS `mindtct` and `bozorth3` are on PATH: extract minutiae for every frame
     in every variant and compute the full pairwise bozorth3 score matrix, then
     summarise genuine (same-finger) vs impostor (different-finger) separation per
     variant. That is the faithful predictor of libfprint behaviour. If NBIS is not
     installed, it still writes the images + metrics and prints how to get NBIS.

Grouping: a frame's "subject" (which finger) is inferred from its filename with the
trailing capture index stripped -- so capture runs labelled per finger group
automatically, e.g.
    rts5812_probe.py ... --capture frame.bin --captures 4 --label index   -> frame_index01..04
    rts5812_probe.py ... --capture frame.bin --captures 3 --label middle   -> frame_middle01..03
then:
    python3 rts5812_match.py frame_index*.bin frame_middle*.bin --out match_out

Requires: numpy, pillow (always); pycryptodome (only to decode .bin frames);
NBIS mindtct + bozorth3 on PATH (optional, for the actual match scores).
"""

import argparse
import itertools
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile

try:
    import numpy as np
except ImportError:
    sys.exit("error: numpy is required -> pip install numpy")
try:
    from PIL import Image
except ImportError:
    sys.exit("error: pillow is required -> pip install pillow")

IMG_W, IMG_H = 135, 62
VARIANTS = ("raw", "stretch", "loceq")


# -- loading -----------------------------------------------------------------

def load_image(path):
    """Return a float32 HxW array for a frame path (.pgm loaded directly; .bin
    decrypted via rts5812_decode using its sibling .blob)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".pgm", ".png", ".bmp"):
        im = Image.open(path).convert("L")
        return np.asarray(im, dtype=np.float32)
    # Raw encrypted frame: decode with the proven offline path.
    try:
        import rts5812_decode as dec
    except ImportError:
        sys.exit("error: rts5812_decode.py must sit next to this script to decode .bin frames")
    frame = open(path, "rb").read()
    blobpath = path + ".blob"
    if not os.path.exists(blobpath):
        sys.exit("error: %s needs its key blob %s to decode" % (path, blobpath))
    blob = open(blobpath, "rb").read()
    K = blob[dec.MASTER_KEY_OFF:dec.MASTER_KEY_OFF + 32]
    f = frame[:dec.FRAME_LEN]
    sid = f[0:8]
    iv = f[dec.IV_OFF:dec.IV_OFF + 16]
    ct = f[dec.CT_OFF:dec.CT_END]
    tag = f[dec.CMAC_OFF:dec.CMAC_OFF + 16]
    cmac_key = dec.kdf(K, sid, 2)
    ctr_key = dec.kdf(K, sid, 1)
    if dec.aes_cmac(cmac_key, f[:dec.CMAC_OFF]) != tag:
        print("  WARNING: %s CMAC mismatch -- wrong blob/SID? image may be garbage" % path)
    pt = dec.AES.new(ctr_key, dec.AES.MODE_CBC, iv).decrypt(ct)
    img = np.frombuffer(pt[dec.IMG_OFF:dec.IMG_OFF + IMG_W * IMG_H], dtype=np.uint8)
    return img.reshape(IMG_H, IMG_W).astype(np.float32)


# -- normalization variants --------------------------------------------------

def box_blur(a, k):
    """Mean over a k x k window, reflect-padded, via an integral image (no scipy)."""
    pad = k // 2
    ap = np.pad(a, pad, mode="reflect")
    cs = np.cumsum(np.cumsum(ap, axis=0), axis=1)
    cs = np.pad(cs, ((1, 0), (1, 0)), mode="constant")
    h, w = a.shape
    S = cs[k:k + h, k:k + w] - cs[0:h, k:k + w] - cs[k:k + h, 0:w] + cs[0:h, 0:w]
    return S / float(k * k)


def pct_stretch(a, lo_p=2, hi_p=98):
    lo, hi = np.percentile(a, lo_p), np.percentile(a, hi_p)
    if hi - lo < 1e-6:
        return np.zeros_like(a)
    return np.clip((a - lo) / (hi - lo) * 255.0, 0, 255)


def variant(img, name, k=11):
    if name == "raw":
        return np.clip(img, 0, 255)
    if name == "stretch":
        return pct_stretch(img)
    if name == "loceq":
        hp = img - box_blur(img, k)           # remove slow illumination, keep ridges
        return pct_stretch(hp)
    raise ValueError("unknown variant %r" % name)


# -- ridge-structure metric --------------------------------------------------

def coherence(img):
    """Orientation coherence in [0,1]: the structure-tensor anisotropy. ~0 for flat
    noise / blank platen, high where ridges flow in a consistent direction. A better
    'finger present with real ridges' signal than raw stddev."""
    gy, gx = np.gradient(img)
    gxx = float(np.sum(gx * gx))
    gyy = float(np.sum(gy * gy))
    gxy = float(np.sum(gx * gy))
    denom = gxx + gyy
    if denom < 1e-9:
        return 0.0
    return ((gxx - gyy) ** 2 + 4 * gxy ** 2) ** 0.5 / denom


def write_pgm(path, arr):
    Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "L").save(path)


# -- NBIS matcher backend ----------------------------------------------------

def nbis_tools():
    return shutil.which("mindtct"), shutil.which("bozorth3")


def extract_xyt(mindtct, png_path, oroot, extra_args):
    """Run mindtct to produce <oroot>.xyt (minutiae). Returns the xyt path or None,
    printing the command + stderr on failure so a format problem is obvious."""
    cmd = [mindtct] + list(extra_args) + [png_path, oroot]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        print("    mindtct failed to launch: %s" % e)
        return None
    xyt = oroot + ".xyt"
    if r.returncode != 0 or not os.path.exists(xyt):
        print("    mindtct error (%s): %s" % (" ".join(cmd), (r.stderr or r.stdout).strip()[:300]))
        return None
    return xyt


def bozorth_score(bozorth3, probe_xyt, gallery_xyt):
    try:
        r = subprocess.run([bozorth3, probe_xyt, gallery_xyt], capture_output=True, text=True)
        return int(r.stdout.strip().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def subject_of(path):
    """Infer the finger/subject from a filename: stem minus a trailing capture index.
    frame_index01.bin -> 'frame_index'; print.pgm -> 'print'."""
    stem = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r"[_-]?\d+$", "", stem) or stem


def summarize(scores_by_pair, subjects, variant_name):
    """scores_by_pair: {(i,j): score}. Split into genuine (same subject) / impostor."""
    genuine, impostor = [], []
    for (i, j), s in scores_by_pair.items():
        if s is None:
            continue
        (genuine if subjects[i] == subjects[j] else impostor).append(s)
    print("\n  [%s] bozorth3 scores" % variant_name)

    def line(label, xs):
        if not xs:
            print("    %-9s (none)" % label)
            return
        xs = sorted(xs)
        print("    %-9s n=%d  min=%d  median=%d  max=%d" %
              (label, len(xs), xs[0], int(statistics.median(xs)), xs[-1]))
    line("genuine", genuine)
    line("impostor", impostor)
    if genuine and impostor:
        gmin, imax = min(genuine), max(impostor)
        # ~40 is the conventional bozorth3 decision threshold libfprint-style matchers use.
        verdict = ("CLEAN separation" if gmin > imax else
                   "OVERLAP (genuine min %d <= impostor max %d)" % (gmin, imax))
        print("    -> %s; conventional accept threshold ~40 -> genuine>=40: %d/%d" %
              (verdict, sum(1 for g in genuine if g >= 40), len(genuine)))
    elif genuine and not impostor:
        print("    -> only same-finger pairs present; add a different finger to test rejection")


def run_matcher(frames, images_by_variant, outdir, variants, mindtct_args):
    mindtct, bozorth3 = nbis_tools()
    if not (mindtct and bozorth3):
        print("\nNBIS not found on PATH (mindtct=%s bozorth3=%s)." %
              (bool(mindtct), bool(bozorth3)))
        print("Falling back to the pure-Python match backend (rts5812_pymatch).")
        print("For the reference matcher, install NBIS so `mindtct`/`bozorth3` are on PATH:")
        print("  - source: https://www.nist.gov/services-resources/software/nist-biometric-image-software-nbis")
        print("  - or build the copy libfprint vendors (libfprint/libfprint, nbis/ subtree).")
        try:
            import rts5812_pymatch as pym
        except ImportError:
            print("  (rts5812_pymatch.py not found next to this script; skipping.)")
            return
        subjects = [subject_of(p) for p in frames]
        pym.run(frames, images_by_variant, subjects, variants, outdir=outdir)
        return
    print("\nNBIS found: mindtct=%s  bozorth3=%s" % (mindtct, bozorth3))
    subjects = [subject_of(p) for p in frames]
    print("subjects: " + ", ".join("%s=%s" % (os.path.basename(p), s)
                                    for p, s in zip(frames, subjects)))
    work = os.path.join(outdir, "_nbis")
    os.makedirs(work, exist_ok=True)
    for vname in variants:
        xyts = []
        for idx, img in enumerate(images_by_variant[vname]):
            png = os.path.join(work, "f%02d_%s.png" % (idx, vname))
            write_pgm(png, img)  # PIL picks PNG from the extension
            oroot = os.path.join(work, "f%02d_%s" % (idx, vname))
            xyts.append(extract_xyt(mindtct, png, oroot, mindtct_args))
        pairs = {}
        for i, j in itertools.combinations(range(len(frames)), 2):
            if xyts[i] and xyts[j]:
                pairs[(i, j)] = bozorth_score(bozorth3, xyts[i], xyts[j])
        n_min = [len(open(x).read().split("\n")) - 1 for x in xyts if x]
        if n_min:
            print("\n  [%s] minutiae per frame: min=%d median=%d max=%d" %
                  (vname, min(n_min), int(statistics.median(n_min)), max(n_min)))
        summarize(pairs, subjects, vname)


# -- main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="RTS5812 offline match-viability harness")
    ap.add_argument("frames", nargs="+", help="frame files (.pgm, or .bin with sibling .blob)")
    ap.add_argument("--out", default="match_out", help="output directory (default match_out)")
    ap.add_argument("--variants", default=",".join(VARIANTS),
                    help="comma list from raw,stretch,loceq (default all)")
    ap.add_argument("--k", type=int, default=11, help="loceq local-mean window (default 11)")
    ap.add_argument("--mindtct-args", default="",
                    help="extra args passed to mindtct (e.g. '-b' for its own contrast boost)")
    args = ap.parse_args()

    variants = [v.strip() for v in args.variants.split(",") if v.strip()]
    for v in variants:
        if v not in VARIANTS:
            sys.exit("unknown variant %r (choose from %s)" % (v, ",".join(VARIANTS)))
    mindtct_args = args.mindtct_args.split() if args.mindtct_args else []

    frames = args.frames
    os.makedirs(args.out, exist_ok=True)
    print("loading %d frame(s)..." % len(frames))
    raw_images = [load_image(p) for p in frames]

    # Per-frame metrics + write every variant image for inspection.
    images_by_variant = {v: [] for v in variants}
    print("\nframe metrics (coherence = ridge-flow strength, 0..1):")
    print("  %-26s %7s %7s %7s %9s" % ("file", "min", "max", "std", "coherence"))
    for p, img in zip(frames, raw_images):
        base = os.path.splitext(os.path.basename(p))[0]
        for v in variants:
            vi = variant(img, v, args.k)
            images_by_variant[v].append(vi)
            write_pgm(os.path.join(args.out, "%s_%s.pgm" % (base, v)), vi)
        coh = coherence(img)
        print("  %-26s %7.1f %7.1f %7.2f %9.3f" %
              (os.path.basename(p), img.min(), img.max(), img.std(), coh))
    print("\nwrote %d variant PGM(s) per frame -> %s/" % (len(variants), args.out))

    run_matcher(frames, images_by_variant, args.out, variants, mindtct_args)
    print("\ndone")


if __name__ == "__main__":
    main()
