"""Single-scale keypoint matcher, built only from C-portable primitives:
box/gaussian blur, sobel, bilinear resize, local-max NMS, 8-bin gradient
histograms, ratio test, 2-point rigid RANSAC."""
import numpy as np, cv2, math

def gblur(a, s): return cv2.GaussianBlur(a, (0, 0), s)

def features(img, scale=4, hp=9, nkp=300, harris_s=2.0, desc_r=None, nb=4, nori=8, rng_seed=0, det='doh', det_s=1.5, border_px=3):
    a = img.astype(np.float32); a = a - cv2.blur(a, (hp, hp), borderType=cv2.BORDER_REFLECT)
    a = cv2.resize(a, None, fx=scale, fy=scale, interpolation=cv2.INTER_LINEAR)
    a = gblur(a, 0.8 * scale / 2)
    gx = cv2.Sobel(a, cv2.CV_32F, 1, 0); gy = cv2.Sobel(a, cv2.CV_32F, 0, 1)
    s = harris_s * scale / 2
    xx, yy, xy = gblur(gx*gx, s), gblur(gy*gy, s), gblur(gx*gy, s)
    if det == 'harris':
        R = xx*yy - xy*xy - 0.04*(xx+yy)**2
    else:   # determinant of Hessian at sigma det_s (native px), scale-normalized
        b = gblur(a, det_s*scale)
        dxx = cv2.Sobel(b, cv2.CV_32F, 2, 0); dyy = cv2.Sobel(b, cv2.CV_32F, 0, 2); dxy = cv2.Sobel(b, cv2.CV_32F, 1, 1)
        R = np.abs(dxx*dyy - dxy*dxy)
    h, w = a.shape
    desc_r = desc_r or int(4 * scale)            # half-size of descriptor window
    border = border_px*scale
    dil = cv2.dilate(R, np.ones((2*scale+1, 2*scale+1), np.uint8))
    ys, xs = np.nonzero((R == dil) & (R > 0))
    keep = (ys >= border) & (ys < h-border) & (xs >= border) & (xs < w-border)
    ys, xs = ys[keep], xs[keep]
    order = np.argsort(-R[ys, xs])[:nkp]; ys, xs = ys[order], xs[order]
    mag = np.hypot(gx, gy); ang = np.arctan2(gy, gx)
    # orientation: smoothed structure-tensor direction (ridge orientation, mod pi),
    # disambiguated by the mean gradient sign in the window
    sw = int(desc_r)
    pts, D = [], []
    oy, ox = np.mgrid[-desc_r:desc_r, -desc_r:desc_r].astype(np.float32) + 0.5
    for y, x in zip(ys, xs):
        wx = xx[y, x]; wy = yy[y, x]; wxy = xy[y, x]
        th = 0.5 * math.atan2(2*wxy, wx - wy)         # dominant gradient dir (mod pi)
        # disambiguate using sum of gradients projected (sign of first moment of intensity)
        m1 = float((cv2.remap(a, (x+ox).astype(np.float32), (y+oy).astype(np.float32), cv2.INTER_NEAREST, borderMode=cv2.BORDER_REFLECT) * (np.cos(th)*ox + np.sin(th)*oy)).sum())
        if m1 < 0: th += math.pi
        c, s_ = math.cos(th), math.sin(th)
        # rotated sample grid
        sx = (x + c*ox - s_*oy).astype(np.float32); sy = (y + s_*ox + c*oy).astype(np.float32)
        pm = cv2.remap(mag, sx, sy, cv2.INTER_LINEAR, borderMode=cv2.BORDER_REFLECT); pa = cv2.remap(ang, sx, sy, cv2.INTER_NEAREST, borderMode=cv2.BORDER_REFLECT) - th
        wgt = np.exp(-(ox**2 + oy**2) / (2*(desc_r*0.8)**2))
        bi = np.floor((pa % (2*math.pi)) / (2*math.pi) * nori).astype(int) % nori
        cell = (2*desc_r) // nb
        cy_, cx_ = (np.floor((oy+desc_r)/cell).astype(int).clip(0, nb-1), np.floor((ox+desc_r)/cell).astype(int).clip(0, nb-1))
        d = np.zeros((nb, nb, nori), np.float32)
        np.add.at(d, (cy_, cx_, bi), pm*wgt)
        d = d.ravel(); d /= np.linalg.norm(d) + 1e-9; d = np.minimum(d, 0.2); d /= np.linalg.norm(d) + 1e-9
        pts.append((x/scale, y/scale)); D.append(d)
    return np.float32(pts).reshape(-1, 2), np.float32(D).reshape(-1, nb*nb*nori)

def rigid_ransac(pa, pb, thr, iters=2000, rng=np.random.default_rng(0)):
    n = len(pa); best = 0
    if n < 2: return 0
    for _ in range(iters):
        i, j = rng.choice(n, 2, replace=False)
        va, vb = pa[j]-pa[i], pb[j]-pb[i]
        la, lb = np.hypot(*va), np.hypot(*vb)
        if la < 3 or abs(la-lb) > 0.1*la: continue
        t = math.atan2(vb[1], vb[0]) - math.atan2(va[1], va[0])
        c, s = math.cos(t), math.sin(t)
        Rm = np.array([[c, -s], [s, c]], np.float32)
        tr = pb[i] - Rm @ pa[i]
        err = np.hypot(*((pa @ Rm.T + tr) - pb).T)
        best = max(best, int((err < thr).sum()))
    return best

def match(fa, fb, ratio=0.85, thr=2.0):
    (pa, da), (pb, db) = fa, fb
    if len(da) < 2 or len(db) < 2: return 0
    d2 = (da**2).sum(1)[:, None] + (db**2).sum(1)[None, :] - 2*da@db.T
    o = np.argsort(d2, 1)[:, :2]
    r = np.take_along_axis(d2, o, 1)
    ok = r[:, 0] < ratio**2 * r[:, 1]
    ia = np.nonzero(ok)[0]; ib = o[ok, 0]
    return rigid_ransac(pa[ia], pb[ib], thr)
