#!/usr/bin/env python3
"""Pure-Python fingerprint match backend for the RTS5812 captures.

This is the dependency-free stand-in for NBIS (mindtct + bozorth3) used by
``rts5812_match.py`` on machines where NBIS cannot be built (e.g. Windows with no
C toolchain). It answers the *same* Step-B question -- do same-finger frames score
clearly above different-finger frames? -- with two INDEPENDENT similarity signals,
so the conclusion does not rest on any single hand-rolled method being perfect:

  1. Minutiae matching (the signal libfprint actually uses):
       orientation field -> global ridge-frequency estimate -> oriented Gabor
       enhancement -> binarize -> Zhang-Suen thinning -> crossing-number minutiae
       -> a simplified Bozorth-style consistent-cluster match score.
  2. Orientation-field phase correlation (a cross-check, hard to get wrong):
       translation-invariant correlation of the two prints' enhanced images; a
       sharp high peak for the same finger, low for a different one.

Everything runs in numpy + pillow. It is deliberately an *approximation* of
bozorth3 -- good enough to de-risk before the C driver, with the reference
bozorth3 run left for a Fedora trip. Each metric is reported separately with its
genuine-vs-impostor split so a disagreement between the two is visible, not hidden.

Used as a library by rts5812_match.py (run_py_matcher). Can also be run directly:
    python3 rts5812_pymatch.py frame_index*.bin frame_middle*.bin
"""

import itertools
import math
import os
import statistics
import sys

import numpy as np


# -- small image helpers -----------------------------------------------------

def _resize(a, scale):
    """Bilinear resize by an integer/float scale, via PIL (no scipy)."""
    from PIL import Image
    h, w = a.shape
    im = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8), "L")
    im = im.resize((int(round(w * scale)), int(round(h * scale))), Image.BILINEAR)
    return np.asarray(im, dtype=np.float32)


def _normalize(a):
    """Zero-mean / unit-std, robust to a flat image."""
    m, s = float(a.mean()), float(a.std())
    if s < 1e-6:
        return np.zeros_like(a)
    return (a - m) / s


def _fft_convolve(img, kernel):
    """2-D linear convolution via FFT, result cropped to img size (zero pad)."""
    ih, iw = img.shape
    kh, kw = kernel.shape
    fh, fw = ih + kh - 1, iw + kw - 1
    F = np.fft.rfft2(img, (fh, fw)) * np.fft.rfft2(kernel, (fh, fw))
    full = np.fft.irfft2(F, (fh, fw))
    # center-crop to original size
    top, left = kh // 2, kw // 2
    return full[top:top + ih, left:left + iw]


# -- orientation field -------------------------------------------------------

def orientation_field(img, block=8, smooth=5):
    """Per-pixel ridge orientation (radians, 0..pi) from gradient structure tensor,
    block-averaged then smoothed. Also returns per-pixel coherence in [0,1]."""
    gy, gx = np.gradient(img)
    gxx = gx * gx
    gyy = gy * gy
    gxy = gx * gy
    # block-sum via box filter (integral image)
    def box(a, k):
        pad = k // 2
        ap = np.pad(a, pad, mode="reflect")
        cs = np.cumsum(np.cumsum(ap, 0), 1)
        cs = np.pad(cs, ((1, 0), (1, 0)))
        h, w = a.shape
        return (cs[k:k + h, k:k + w] - cs[0:h, k:k + w]
                - cs[k:k + h, 0:w] + cs[0:h, 0:w])
    Sxx = box(gxx, block)
    Syy = box(gyy, block)
    Sxy = box(gxy, block)
    # double-angle averaging then smooth
    Vx = 2 * Sxy
    Vy = Sxx - Syy
    Vx = box(Vx, smooth)
    Vy = box(Vy, smooth)
    theta = 0.5 * np.arctan2(Vx, Vy)      # gradient angle
    orient = theta + math.pi / 2.0        # ridge angle perpendicular to gradient
    orient = np.mod(orient, math.pi)
    mag = np.sqrt(Vx * Vx + Vy * Vy)
    denom = Sxx + Syy
    coh = np.where(denom > 1e-9, mag / denom, 0.0)
    return orient.astype(np.float32), coh.astype(np.float32)


# -- ridge frequency ---------------------------------------------------------

def ridge_wavelength(img, orient):
    """Estimate a single dominant ridge wavelength (pixels) from the power spectrum
    of the (high-passed) image. Clamped to a sane band for a flat-press sensor."""
    a = img - img.mean()
    win = np.outer(np.hanning(a.shape[0]), np.hanning(a.shape[1]))
    F = np.fft.fftshift(np.abs(np.fft.fft2(a * win)))
    h, w = F.shape
    cy, cx = h // 2, w // 2
    yy, xx = np.mgrid[0:h, 0:w]
    r = np.sqrt((yy - cy) ** 2 + (xx - cx) ** 2)
    # radial power, ignore DC and very high freq
    rmax = min(cy, cx)
    rad = np.zeros(rmax)
    for rr in range(2, rmax):
        m = (r >= rr - 0.5) & (r < rr + 0.5)
        if m.any():
            rad[rr] = F[m].mean()
    if rad.max() <= 0:
        return 8.0
    peak = int(np.argmax(rad))
    if peak < 2:
        return 8.0
    wl = min(h, w) / float(peak)          # wavelength in pixels
    return float(np.clip(wl, 4.0, 16.0))


# -- Gabor enhancement -------------------------------------------------------

def _gabor_kernel(theta, wavelength, ksize=None):
    freq = 1.0 / wavelength
    sigma = 0.56 * wavelength             # ~0.56*lambda gives ~1 octave bandwidth
    if ksize is None:
        ksize = int(2 * round(3 * sigma) + 1)
    half = ksize // 2
    y, x = np.mgrid[-half:half + 1, -half:half + 1]
    xr = x * math.cos(theta) + y * math.sin(theta)
    yr = -x * math.sin(theta) + y * math.cos(theta)
    g = np.exp(-0.5 * (xr * xr + yr * yr) / (sigma * sigma)) * np.cos(2 * math.pi * freq * xr)
    g -= g.mean()                         # zero DC so flat areas -> 0
    return g.astype(np.float32)


def gabor_enhance(img, orient, wavelength, n_orient=16):
    """Filter the image with a bank of oriented Gabor kernels and, per pixel, take
    the response of the kernel nearest the local ridge orientation."""
    img = _normalize(img)
    angles = [k * math.pi / n_orient for k in range(n_orient)]
    responses = np.stack([_fft_convolve(img, _gabor_kernel(a, wavelength))
                          for a in angles], axis=0)
    # index of nearest orientation bin per pixel
    idx = np.mod(np.round(orient / (math.pi / n_orient)).astype(int), n_orient)
    out = np.take_along_axis(responses, idx[None, :, :], axis=0)[0]
    return out


# -- binarize + Zhang-Suen thinning -----------------------------------------

def binarize(enh, coh, coh_thresh=None):
    """Ridges = positive Gabor response in regions of real ridge flow."""
    b = enh > 0
    if coh_thresh is None:
        coh_thresh = max(np.percentile(coh, 40), 1e-6)
    mask = coh >= coh_thresh
    return (b & mask).astype(np.uint8), mask


def zhang_suen(binary):
    """Zhang-Suen thinning to a 1-pixel skeleton (vectorized per sub-iteration)."""
    img = binary.copy().astype(np.uint8)
    def neighbors(a):
        P = {}
        P[2] = np.roll(a, -1, 0)                       # north
        P[3] = np.roll(np.roll(a, -1, 0), 1, 1)        # north-east
        P[4] = np.roll(a, 1, 1)                         # east
        P[5] = np.roll(np.roll(a, 1, 0), 1, 1)         # south-east
        P[6] = np.roll(a, 1, 0)                         # south
        P[7] = np.roll(np.roll(a, 1, 0), -1, 1)        # south-west
        P[8] = np.roll(a, -1, 1)                        # west
        P[9] = np.roll(np.roll(a, -1, 0), -1, 1)       # north-west
        return P
    changed = True
    while changed:
        changed = False
        for step in (0, 1):
            P = neighbors(img)
            seq = [P[i] for i in (2, 3, 4, 5, 6, 7, 8, 9)]
            B = sum(seq)                                 # number of ridge neighbors
            # transitions 0->1 in the ordered sequence P2..P9,P2
            A = np.zeros_like(img, dtype=np.int32)
            order = seq + [P[2]]
            for i in range(8):
                A += ((order[i] == 0) & (order[i + 1] == 1)).astype(np.int32)
            if step == 0:
                c1 = (P[2] * P[4] * P[6] == 0)
                c2 = (P[4] * P[6] * P[8] == 0)
            else:
                c1 = (P[2] * P[4] * P[8] == 0)
                c2 = (P[2] * P[6] * P[8] == 0)
            cond = (img == 1) & (B >= 2) & (B <= 6) & (A == 1) & c1 & c2
            if cond.any():
                img[cond] = 0
                changed = True
    return img


# -- minutiae ----------------------------------------------------------------

def extract_minutiae(skel, orient, coh, mask, margin=12, min_sep=8, cap=50):
    """Crossing-number minutiae from a skeleton. Returns a list of
    (x, y, theta, type, quality), keeping only the `cap` highest-quality points
    (quality = local orientation coherence) spaced at least `min_sep` apart."""
    h, w = skel.shape
    P = {}
    P[2] = np.roll(skel, -1, 0)
    P[3] = np.roll(np.roll(skel, -1, 0), 1, 1)
    P[4] = np.roll(skel, 1, 1)
    P[5] = np.roll(np.roll(skel, 1, 0), 1, 1)
    P[6] = np.roll(skel, 1, 0)
    P[7] = np.roll(np.roll(skel, 1, 0), -1, 1)
    P[8] = np.roll(skel, -1, 1)
    P[9] = np.roll(np.roll(skel, -1, 0), -1, 1)
    order = [P[i] for i in (2, 3, 4, 5, 6, 7, 8, 9)] + [P[2]]
    cn = np.zeros_like(skel, dtype=np.int32)
    for i in range(8):
        cn += np.abs(order[i].astype(np.int32) - order[i + 1].astype(np.int32))
    cn = cn // 2
    minut = []
    ys, xs = np.where(skel == 1)
    for y, x in zip(ys, xs):
        if x < margin or y < margin or x >= w - margin or y >= h - margin:
            continue
        if not mask[y, x]:
            continue
        c = cn[y, x]
        if c == 1:
            mtype = "end"
        elif c == 3:
            mtype = "bif"
        else:
            continue
        minut.append((int(x), int(y), float(orient[y, x]), mtype, float(coh[y, x])))
    # highest-quality first, then greedily drop points too close to a kept one
    minut.sort(key=lambda m: m[4], reverse=True)
    kept = []
    for m in minut:
        if all((m[0] - k[0]) ** 2 + (m[1] - k[1]) ** 2 >= min_sep * min_sep for k in kept):
            kept.append(m)
        if len(kept) >= cap:
            break
    return kept


# -- full extraction per image -----------------------------------------------

def fingerprint_template(img, scale=2.0):
    """Image -> (minutiae list, enhanced image, debug dict). Upscales first so the
    thinning/crossing-number step has enough ridge width to be stable."""
    up = _resize(img, scale)
    orient, coh = orientation_field(up, block=8, smooth=7)
    wl = ridge_wavelength(up, orient)
    enh = gabor_enhance(up, orient, wl, n_orient=16)
    binr, mask = binarize(enh, coh)
    skel = zhang_suen(binr)
    minut = extract_minutiae(skel, orient, coh, mask,
                             margin=int(2 * scale) + 6, min_sep=int(5 * scale), cap=50)
    dbg = dict(wavelength=wl, n_minutiae=len(minut), enh=enh, skel=skel, binr=binr,
               coh=coh, mask=mask, shape=up.shape)
    return minut, enh, dbg


# -- Bozorth-style minutiae matcher ------------------------------------------

def match_minutiae(ma, mb, rot_max=math.radians(40), rot_bin=math.radians(12),
                   trans_bin=14.0):
    """Generalized-Hough alignment matcher (a standard, fast minutiae matcher).

    For every candidate correspondence (minutia i in A, j in B) we hypothesize the
    rigid transform that maps A onto B implied by their positions and ridge angles,
    and vote in a quantized (rotation, tx, ty) accumulator. The fullest bin's vote
    count is the number of minutiae that line up under one consistent alignment --
    a bozorth3-like match magnitude (genuine prints produce a tall peak, impostors
    a flat scatter). O(N*M), vectorized. Returns the peak vote count (an int)."""
    if not ma or not mb:
        return 0
    A = np.asarray([(x, y, th) for (x, y, th, _, _) in ma], dtype=np.float64)
    B = np.asarray([(x, y, th) for (x, y, th, _, _) in mb], dtype=np.float64)
    xa, ya, ta = A[:, 0][:, None], A[:, 1][:, None], A[:, 2][:, None]   # (N,1)
    xb, yb, tb = B[:, 0][None, :], B[:, 1][None, :], B[:, 2][None, :]   # (1,M)
    # ridge orientation is mod pi; rotation hypothesis wrapped into (-pi/2, pi/2]
    r = (tb - ta + math.pi / 2) % math.pi - math.pi / 2                 # (N,M)
    cos_r, sin_r = np.cos(r), np.sin(r)
    tx = xb - (cos_r * xa - sin_r * ya)
    ty = yb - (sin_r * xa + cos_r * ya)
    N, M = r.shape
    ii = np.repeat(np.arange(N), M).reshape(N, M)
    keep = np.abs(r) <= rot_max
    if not keep.any():
        return 0
    rq = np.round(r[keep] / rot_bin).astype(np.int64)
    txq = np.round(tx[keep] / trans_bin).astype(np.int64)
    tyq = np.round(ty[keep] / trans_bin).astype(np.int64)
    iq = ii[keep]
    keys = rq * 1_000_000 + txq * 1000 + tyq
    if keys.size == 0:
        return 0
    # the fullest alignment bin, scored by the number of DISTINCT probe minutiae in
    # it (so one minutia matching several candidates in the same bin counts once)
    uniq, counts = np.unique(keys, return_counts=True)
    best_key = uniq[int(counts.argmax())]
    sel = keys == best_key
    return int(np.unique(iq[sel]).size)


# -- PRIMARY signal: coherence-masked ridge cross-correlation ----------------
#
# Minutiae extraction on these tiny, faint frames is too noisy without NBIS's real
# Gabor+thinning (our pure-Python enhancer hallucinates ridges in low-contrast
# regions -- see the dev notes), so the minutiae matcher above is kept only as a
# clearly-labelled EXPERIMENTAL cross-check. The signal we actually trust for the
# Step-B de-risk is a direct measurement that does not invent anything: band-pass
# the real ridges, keep only high-coherence pixels, and ask whether one frame's
# ridge pattern lines up with another's under a small rigid transform.

def ridge_template(img, scale=2.0, coh_pct=55):
    """Image -> (bandpassed ridge image, coherence mask). Upscales, isolates the
    ridge band with a difference-of-boxes band-pass, and masks to pixels with real
    oriented ridge flow (coherence above the `coh_pct` percentile)."""
    import rts5812_match as rm            # reuse its box_blur (integral-image)
    up = _resize(img, scale)
    bp = rm.box_blur(up, 3) - rm.box_blur(up, 15)
    _, coh = orientation_field(up, block=8, smooth=7)
    mask = coh > np.percentile(coh, coh_pct)
    return bp.astype(np.float32), mask


def _rotate(a, deg):
    from PIL import Image
    im = Image.fromarray(((a - a.min()) / (np.ptp(a) + 1e-9) * 255).astype(np.uint8), "L")
    return np.asarray(im.rotate(deg, resample=Image.BILINEAR), dtype=np.float32)


def ridge_correlation(a_bp, a_mask, b_bp, b_mask, maxshift=24, step=2,
                      rots=range(-12, 13, 4), min_overlap=300):
    """Best normalized cross-correlation of two band-passed ridge images over a
    small rigid search (integer shifts +/- maxshift, rotations `rots`), computed
    only on the overlap of both coherence masks. ~1.0 = same ridge pattern aligned,
    ~0 = unrelated. Translation/rotation tolerant and invents nothing -- a genuine
    pair with real overlap peaks high, an impostor stays low."""
    best = -1.0
    h, w = a_bp.shape
    for dg in rots:
        bb = b_bp if dg == 0 else _rotate(b_bp, dg)
        mbb = b_mask if dg == 0 else (_rotate(b_mask.astype(np.float32), dg) > 0.5)
        for dy in range(-maxshift, maxshift + 1, step):
            for dx in range(-maxshift, maxshift + 1, step):
                ay0, ay1 = max(0, dy), min(h, h + dy)
                ax0, ax1 = max(0, dx), min(w, w + dx)
                by0, by1 = max(0, -dy), min(h, h - dy)
                bx0, bx1 = max(0, -dx), min(w, w - dx)
                m = a_mask[ay0:ay1, ax0:ax1] & mbb[by0:by1, bx0:bx1]
                if m.sum() < min_overlap:
                    continue
                A = a_bp[ay0:ay1, ax0:ax1][m]
                B = bb[by0:by1, bx0:bx1][m]
                A = A - A.mean()
                B = B - B.mean()
                d = math.sqrt(float((A * A).sum()) * float((B * B).sum())) + 1e-9
                v = float((A * B).sum()) / d
                if v > best:
                    best = v
    return best


# -- driver over a set of frames ---------------------------------------------

def run(frames, images_by_variant, subjects, variants, outdir=None, verbose=True,
        primary_variant="stretch"):
    """Score every frame pair with the trusted ridge-correlation signal (on the
    `primary_variant` images) and report genuine/impostor separation, a rank-1
    identification table (the realistic enrollment view), plus the experimental
    minutiae cross-check. Returns a results dict."""
    n = len(frames)
    short = [os.path.splitext(os.path.basename(f))[0].replace("frame_", "") for f in frames]

    # ridge templates from the chosen normalization variant
    pv = primary_variant if primary_variant in images_by_variant else variants[0]
    imgs = images_by_variant[pv]
    templ = [ridge_template(im) for im in imgs]
    S = np.full((n, n), np.nan)
    for i, j in itertools.combinations(range(n), 2):
        s = ridge_correlation(templ[i][0], templ[i][1], templ[j][0], templ[j][1])
        S[i, j] = S[j, i] = s

    genuine = [S[i, j] for i, j in itertools.combinations(range(n), 2) if subjects[i] == subjects[j]]
    impostor = [S[i, j] for i, j in itertools.combinations(range(n), 2) if subjects[i] != subjects[j]]

    if verbose:
        print("\n=== python match-viability result (ridge-correlation on '%s') ===" % pv)
        print("  NOTE: a pure-Python proxy for NBIS bozorth3 -- it measures whether")
        print("  identity is RECOVERABLE from these frames, not exact bozorth3 scores.")
        _split("ridge-correlation (same vs different finger)", genuine, impostor, "%.3f")

        # rank-1 identification: each frame probed against all the others.
        print("\n  [rank-1 identification: does each press match its OWN finger best?]")
        correct = 0
        for i in range(n):
            others = [(S[i, j], subjects[j], short[j]) for j in range(n) if j != i and not np.isnan(S[i, j])]
            if not others:
                continue
            bestg = max((s for s, sj, _ in others if sj == subjects[i]), default=float("nan"))
            besti = max((s for s, sj, _ in others if sj != subjects[i]), default=float("nan"))
            top = max(others)
            ok = top[1] == subjects[i]
            correct += ok
            print("    %-12s bestGEN=%.3f bestIMP=%.3f  -> %s" %
                  (short[i], bestg, besti, "OK" if ok else "MISID as %s" % top[2]))
        print("    => %d/%d presses identify their own finger (best genuine > best impostor)" %
              (correct, n))

        if genuine and impostor:
            auc = sum((g > i) + 0.5 * (g == i) for g in genuine for i in impostor) / (len(genuine) * len(impostor))
            pooled = ((statistics.pstdev(genuine) ** 2 + statistics.pstdev(impostor) ** 2) / 2) ** 0.5
            dpr = (statistics.mean(genuine) - statistics.mean(impostor)) / (pooled + 1e-9)
            print("\n  pairwise separation: AUC=%.3f  d'=%.2f (genuine>impostor)" % (auc, dpr))

    # experimental minutiae cross-check (not the verdict)
    mm = None
    if verbose:
        templates = [fingerprint_template(im)[0] for im in imgs]
        mm = {}
        for i, j in itertools.combinations(range(n), 2):
            mm[(i, j)] = match_minutiae(templates[i], templates[j])
        g2 = [mm[k] for k in mm if subjects[k[0]] == subjects[k[1]]]
        i2 = [mm[k] for k in mm if subjects[k[0]] != subjects[k[1]]]
        print("\n  [EXPERIMENTAL pure-Python minutiae matcher -- noisy at this resolution,")
        print("   shown for context only; NOT used for the verdict above]")
        _split("minutiae-match score", g2, i2, "%.0f", indent=3)

    return dict(variant=pv, score_matrix=S, genuine=genuine, impostor=impostor,
                subjects=subjects, frames=frames, minutiae=mm)


def _split(label, genuine, impostor, fmt="%.3f", indent=1):
    pad = "  " * indent
    print("%s[%s]" % (pad, label))
    def line(name, xs):
        if not xs:
            print("%s  %-9s (none)" % (pad, name))
            return
        xs = sorted(xs)
        print(("%s  %-9s n=%d  min=" + fmt + "  median=" + fmt + "  max=" + fmt) %
              (pad, name, len(xs), xs[0], statistics.median(xs), xs[-1]))
    line("genuine", genuine)
    line("impostor", impostor)
    if genuine and impostor:
        gmed, imed = statistics.median(genuine), statistics.median(impostor)
        verdict = "genuine median ABOVE impostor" if gmed > imed else "NO median separation"
        tail = "" if min(genuine) > max(impostor) else "  (distributions overlap)"
        print(("%s  -> %s (" + fmt + " vs " + fmt + ")%s") % (pad, verdict, gmed, imed, tail))


def _standalone():
    import rts5812_match as rm
    frames = sys.argv[1:]
    if not frames:
        sys.exit("usage: rts5812_pymatch.py <frame...>")
    imgs = [rm.load_image(p) for p in frames]
    variants = list(rm.VARIANTS)
    ibv = {v: [rm.variant(im, v) for im in imgs] for v in variants}
    subjects = [rm.subject_of(p) for p in frames]
    run(frames, ibv, subjects, variants)


if __name__ == "__main__":
    _standalone()
