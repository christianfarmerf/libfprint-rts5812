/*
 * Keypoint matcher for RTS5812 frames. See rts5812_match.h for why this exists.
 *
 * Pipeline (a C port of the prototype that was validated offline on dataset2):
 *   1. high-pass the native frame (subtract a 9x9 box mean), upscale x3 bilinear,
 *      light Gaussian smoothing;
 *   2. detector: |det Hessian| at sigma = 1 native px, 7x7 non-max suppression,
 *      strongest RTS5812_MAX_KP kept;
 *   3. orientation: structure-tensor gradient direction (mod pi), its sign fixed
 *      by the first intensity moment along it;
 *   4. descriptor: 4x4 cells x 8 orientation bins of Gaussian-weighted gradient
 *      magnitude over a rotated window of radius 8 native px (reflect borders,
 *      so keypoints near the frame edge still get full descriptors), L2
 *      normalized, clipped at 0.2, renormalized (as in SIFT);
 *   5. matching: nearest neighbour with a 0.9 ratio test, then 2-point rigid
 *      RANSAC; the score is the largest inlier set (1.5 native px tolerance).
 * Single scale is deliberate: one sensor, so there is never a scale change.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "rts5812_match.h"

#define RTS5812_UPSCALE     3      /* native -> working resolution          */
#define RTS5812_HP_BOX      9      /* high-pass box size, native px          */
#define RTS5812_PRE_SIGMA   1.2f   /* smoothing after upscale, working px   */
#define RTS5812_TENSOR_SIGMA 3.0f  /* structure-tensor window, working px   */
#define RTS5812_DOH_SIGMA   3.0f   /* Hessian scale, working px (1 native)   */
#define RTS5812_NMS_RADIUS  3      /* 7x7 non-max suppression                */
#define RTS5812_BORDER      9      /* no keypoints this close to the edge    */
G_STATIC_ASSERT (RTS5812_BORDER >= RTS5812_NMS_RADIUS);
#define RTS5812_MAX_KP      600
#define RTS5812_DESC_R      24     /* descriptor half-size, working px       */
#define RTS5812_NCELL       4
#define RTS5812_NORI        8
#define RTS5812_DESC_LEN    (RTS5812_NCELL * RTS5812_NCELL * RTS5812_NORI)
#define RTS5812_RATIO       0.9f
#define RTS5812_RANSAC_ITERS 2000
/* Inlier tolerance, native px. 1.5 rather than 2 lowers the chance-agreement
 * floor (different-finger best-of-10 max 6 -> 5 on dataset2) for ~1-2 points
 * of FRR; requiring unique inliers or bounding rotation changed nothing. */
#define RTS5812_RANSAC_TOL  1.5f

struct _Rts5812Features
{
  int    n;
  float *pts;    /* n x (x, y), native pixel coordinates */
  guint8 *desc;  /* n x RTS5812_DESC_LEN, SIFT-style 8-bit  */
};

typedef struct
{
  int    w, h;
  float *d;
} Plane;

static Plane
plane_new (int w, int h)
{
  Plane p = { w, h, g_new0 (float, (gsize) w * h) };

  return p;
}

static void
plane_free (Plane *p)
{
  g_clear_pointer (&p->d, g_free);
}

/* Reflect-101 index (OpenCV's default border): -1 -> 1, n -> n-2. */
static inline int
reflect (int i, int n)
{
  if (n == 1)
    return 0;
  while (i < 0 || i >= n)
    i = i < 0 ? -i : 2 * n - 2 - i;
  return i;
}

static inline float
at (const Plane *p, int x, int y)
{
  return p->d[reflect (y, p->h) * p->w + reflect (x, p->w)];
}

static inline float
at_bilinear (const Plane *p, float x, float y)
{
  int x0 = (int) floorf (x), y0 = (int) floorf (y);
  float fx = x - x0, fy = y - y0;

  return (1 - fy) * ((1 - fx) * at (p, x0, y0) + fx * at (p, x0 + 1, y0)) +
         fy * ((1 - fx) * at (p, x0, y0 + 1) + fx * at (p, x0 + 1, y0 + 1));
}

/* Separable convolution with odd-length kernels kx (len 2*rx+1), ky (2*ry+1). */
static void
conv_sep (const Plane *src, Plane *dst, const float *kx, int rx,
          const float *ky, int ry)
{
  const int w = src->w, h = src->h;
  Plane tmp = plane_new (w, h);
  /* reflected source index for every (output position, tap): no per-tap
   * border logic in the inner loops */
  g_autofree int *ix = g_new (int, (gsize) w * (2 * rx + 1));
  g_autofree int *iy = g_new (int, (gsize) h * (2 * ry + 1));

  for (int x = 0; x < w; x++)
    for (int k = -rx; k <= rx; k++)
      ix[x * (2 * rx + 1) + k + rx] = reflect (x + k, w);
  for (int y = 0; y < h; y++)
    for (int k = -ry; k <= ry; k++)
      iy[y * (2 * ry + 1) + k + ry] = reflect (y + k, h) * w;

  for (int y = 0; y < h; y++)
    {
      const float *row = src->d + y * w;
      for (int x = 0; x < w; x++)
        {
          const int *t = ix + x * (2 * rx + 1);
          float s = 0;
          for (int k = 0; k <= 2 * rx; k++)
            s += kx[k] * row[t[k]];
          tmp.d[y * w + x] = s;
        }
    }
  /* vertical pass row-wise, so the inner loop runs along contiguous memory */
  for (int y = 0; y < h; y++)
    {
      float *out = dst->d + y * w;
      const int *t = iy + y * (2 * ry + 1);
      memset (out, 0, sizeof (float) * w);
      for (int k = 0; k <= 2 * ry; k++)
        {
          const float *row = tmp.d + t[k];
          const float c = ky[k];
          for (int x = 0; x < w; x++)
            out[x] += c * row[x];
        }
    }
  plane_free (&tmp);
}

static void
gauss_blur (const Plane *src, Plane *dst, float sigma)
{
  int r = (int) ceilf (4 * sigma);
  g_autofree float *k = g_new (float, 2 * r + 1);
  float sum = 0;

  for (int i = -r; i <= r; i++)
    sum += k[i + r] = expf (-0.5f * i * i / (sigma * sigma));
  for (int i = 0; i <= 2 * r; i++)
    k[i] /= sum;
  conv_sep (src, dst, k, r, k, r);
}

static const float k_deriv[3]  = { -1, 0, 1 };
static const float k_deriv2[3] = { 1, -2, 1 };
static const float k_smooth[3] = { 1, 2, 1 };

static void
sobel (const Plane *src, Plane *dst, const float *kx, const float *ky)
{
  conv_sep (src, dst, kx, 1, ky, 1);
}

/* Copy of p with a reflect-101 margin of `m` on every side, so window sampling
 * that may run past the frame edge needs no per-sample border handling. */
typedef struct
{
  int    w, m;     /* padded width, margin */
  float *d;
} Padded;

static Padded
pad_plane (const Plane *p, int m)
{
  Padded q = { p->w + 2 * m, m, g_new (float, (gsize) (p->w + 2 * m) * (p->h + 2 * m)) };

  for (int y = -m; y < p->h + m; y++)
    for (int x = -m; x < p->w + m; x++)
      q.d[(y + m) * q.w + x + m] = at (p, x, y);
  return q;
}

/* floor() for values > -1024 (all sample coordinates here are bounded below
 * by the padding margin): truncation after an offset, avoiding a libm call
 * per sample on baseline x86-64 (no SSE4.1 roundss). */
static inline int
ffloor (float v)
{
  return (int) (v + 1024.0f) - 1024;
}

static inline float
pad_at (const Padded *q, int x, int y)
{
  return q->d[(y + q->m) * q->w + x + q->m];
}

static inline float
pad_bilinear (const Padded *q, float x, float y)
{
  int x0 = ffloor (x), y0 = ffloor (y);
  float fx = x - x0, fy = y - y0;
  const float *r0 = q->d + (y0 + q->m) * q->w + x0 + q->m, *r1 = r0 + q->w;

  return (1 - fy) * ((1 - fx) * r0[0] + fx * r0[1]) +
         fy * ((1 - fx) * r1[0] + fx * r1[1]);
}

typedef struct
{
  int   x, y;
  float r;
} Cand;

static int
cand_cmp (const void *a, const void *b)
{
  float ra = ((const Cand *) a)->r, rb = ((const Cand *) b)->r;

  return (ra < rb) - (ra > rb);   /* descending */
}

Rts5812Features *
rts5812_features_extract (const guint8 *img, int nw, int nh)
{
  const int S = RTS5812_UPSCALE;
  const int w = nw * S, h = nh * S;
  Rts5812Features *f = g_new0 (Rts5812Features, 1);
  Plane nat = plane_new (nw, nh), hp = plane_new (nw, nh);
  Plane up = plane_new (w, h), a = plane_new (w, h);
  Plane gx = plane_new (w, h), gy = plane_new (w, h);
  Plane txx = plane_new (w, h), tyy = plane_new (w, h), txy = plane_new (w, h);
  Plane mag = plane_new (w, h), ang = plane_new (w, h), resp = plane_new (w, h);
  float box[RTS5812_HP_BOX];
  const int br = RTS5812_HP_BOX / 2;

  /* 1. high-pass at native resolution, upscale, smooth */
  for (int i = 0; i < nw * nh; i++)
    nat.d[i] = img[i];
  for (int i = 0; i < RTS5812_HP_BOX; i++)
    box[i] = 1.0f / RTS5812_HP_BOX;
  conv_sep (&nat, &hp, box, br, box, br);
  for (int i = 0; i < nw * nh; i++)
    hp.d[i] = nat.d[i] - hp.d[i];
  for (int y = 0; y < h; y++)
    for (int x = 0; x < w; x++)
      {
        /* half-pixel-centre bilinear, clamped (OpenCV INTER_LINEAR) */
        float sx = CLAMP ((x + 0.5f) / S - 0.5f, 0, nw - 1);
        float sy = CLAMP ((y + 0.5f) / S - 0.5f, 0, nh - 1);
        up.d[y * w + x] = at_bilinear (&hp, sx, sy);
      }
  gauss_blur (&up, &a, RTS5812_PRE_SIGMA);

  /* gradients, magnitude/angle, smoothed structure tensor */
  sobel (&a, &gx, k_deriv, k_smooth);
  sobel (&a, &gy, k_smooth, k_deriv);
  {
    Plane p = plane_new (w, h);
    for (int i = 0; i < w * h; i++)
      {
        mag.d[i] = hypotf (gx.d[i], gy.d[i]);
        ang.d[i] = atan2f (gy.d[i], gx.d[i]);
      }
    for (int i = 0; i < w * h; i++)
      p.d[i] = gx.d[i] * gx.d[i];
    gauss_blur (&p, &txx, RTS5812_TENSOR_SIGMA);
    for (int i = 0; i < w * h; i++)
      p.d[i] = gy.d[i] * gy.d[i];
    gauss_blur (&p, &tyy, RTS5812_TENSOR_SIGMA);
    for (int i = 0; i < w * h; i++)
      p.d[i] = gx.d[i] * gy.d[i];
    gauss_blur (&p, &txy, RTS5812_TENSOR_SIGMA);
    plane_free (&p);
  }

  /* 2. |det Hessian| detector */
  {
    Plane b = plane_new (w, h), dxx = plane_new (w, h);
    Plane dyy = plane_new (w, h), dxy = plane_new (w, h);
    gauss_blur (&a, &b, RTS5812_DOH_SIGMA);
    sobel (&b, &dxx, k_deriv2, k_smooth);
    sobel (&b, &dyy, k_smooth, k_deriv2);
    sobel (&b, &dxy, k_deriv, k_deriv);
    for (int i = 0; i < w * h; i++)
      resp.d[i] = fabsf (dxx.d[i] * dyy.d[i] - dxy.d[i] * dxy.d[i]);
    plane_free (&b);
    plane_free (&dxx);
    plane_free (&dyy);
    plane_free (&dxy);
  }

  g_autoptr(GArray) cands = g_array_new (FALSE, FALSE, sizeof (Cand));
  for (int y = RTS5812_BORDER; y < h - RTS5812_BORDER; y++)
    for (int x = RTS5812_BORDER; x < w - RTS5812_BORDER; x++)
      {
        float r = resp.d[y * w + x];
        gboolean is_max = r > 0;
        for (int dy = -RTS5812_NMS_RADIUS; is_max && dy <= RTS5812_NMS_RADIUS; dy++)
          for (int dx = -RTS5812_NMS_RADIUS; dx <= RTS5812_NMS_RADIUS; dx++)
            if (resp.d[(y + dy) * w + x + dx] > r)
              {
                is_max = FALSE;
                break;
              }
        if (is_max)
          {
            Cand c = { x, y, r };
            g_array_append_val (cands, c);
          }
      }
  g_array_sort (cands, cand_cmp);
  f->n = MIN ((int) cands->len, RTS5812_MAX_KP);
  f->pts = g_new (float, 2 * MAX (f->n, 1));
  f->desc = g_new0 (guint8, (gsize) RTS5812_DESC_LEN * MAX (f->n, 1));

  /* 3+4. orientation and descriptor per keypoint. A rotated window reaches
   * R*sqrt(2) from its centre; centres sit >= RTS5812_BORDER inside, so this
   * margin covers every sample (+2 for bilinear and rounding). */
  const int R = RTS5812_DESC_R, cell = 2 * R / RTS5812_NCELL;
  const int margin = (int) ceilf (R * G_SQRT2) - RTS5812_BORDER + 2;
  Padded pa_a = pad_plane (&a, margin), pa_mag = pad_plane (&mag, margin);
  Padded pa_ang = pad_plane (&ang, margin);
  const float wsig = 0.8f * R;
  g_autofree float *wtab = g_new (float, 4 * R * R);
  float d[RTS5812_DESC_LEN];

  for (int iy = 0; iy < 2 * R; iy++)
    for (int ix = 0; ix < 2 * R; ix++)
      {
        float ox = ix - R + 0.5f, oy = iy - R + 0.5f;
        wtab[iy * 2 * R + ix] = expf (-(ox * ox + oy * oy) / (2 * wsig * wsig));
      }
  for (int k = 0; k < f->n; k++)
    {
      const Cand *c = &g_array_index (cands, Cand, k);
      int i = c->y * w + c->x;
      float th = 0.5f * atan2f (2 * txy.d[i], txx.d[i] - tyy.d[i]);
      float ct = cosf (th), st = sinf (th), m1 = 0;
      guint8 *q = f->desc + (gsize) k * RTS5812_DESC_LEN;
      float norm = 0;

      memset (d, 0, sizeof d);

      for (int iy = 0; iy < 2 * R; iy++)
        for (int ix = 0; ix < 2 * R; ix++)
          {
            float ox = ix - R + 0.5f, oy = iy - R + 0.5f;
            m1 += pad_at (&pa_a, ffloor (c->x + ox + 0.5f), ffloor (c->y + oy + 0.5f)) *
                  (ct * ox + st * oy);
          }
      if (m1 < 0)
        {
          th += G_PI;
          ct = -ct;
          st = -st;
        }

      for (int iy = 0; iy < 2 * R; iy++)
        for (int ix = 0; ix < 2 * R; ix++)
          {
            float ox = ix - R + 0.5f, oy = iy - R + 0.5f;
            float sx = c->x + ct * ox - st * oy, sy = c->y + st * ox + ct * oy;
            float m = pad_bilinear (&pa_mag, sx, sy);
            float pa = pad_at (&pa_ang, ffloor (sx + 0.5f), ffloor (sy + 0.5f)) - th;
            float wt = wtab[iy * 2 * R + ix];
            int bin, cx = MIN (ix / cell, RTS5812_NCELL - 1), cy = MIN (iy / cell, RTS5812_NCELL - 1);

            /* ang in [-pi, pi], th in [-pi/2, 3pi/2]: two folds at most */
            while (pa < 0)
              pa += 2 * G_PI;
            while (pa >= 2 * G_PI)
              pa -= 2 * G_PI;
            bin = (int) (pa * (RTS5812_NORI / (2 * G_PI))) % RTS5812_NORI;
            d[(cy * RTS5812_NCELL + cx) * RTS5812_NORI + bin] += m * wt;
          }
      for (int j = 0; j < RTS5812_DESC_LEN; j++)
        norm += d[j] * d[j];
      norm = sqrtf (norm) + 1e-9f;
      for (int j = 0; j < RTS5812_DESC_LEN; j++)
        d[j] = MIN (d[j] / norm, 0.2f);
      norm = 0;
      for (int j = 0; j < RTS5812_DESC_LEN; j++)
        norm += d[j] * d[j];
      norm = sqrtf (norm) + 1e-9f;
      for (int j = 0; j < RTS5812_DESC_LEN; j++)
        q[j] = (guint8) MIN (512.0f * d[j] / norm + 0.5f, 255.0f);

      f->pts[2 * k] = (float) c->x / S;
      f->pts[2 * k + 1] = (float) c->y / S;
    }

  plane_free (&nat);
  plane_free (&hp);
  plane_free (&up);
  plane_free (&a);
  plane_free (&gx);
  plane_free (&gy);
  plane_free (&txx);
  plane_free (&tyy);
  plane_free (&txy);
  g_free (pa_a.d);
  g_free (pa_mag.d);
  g_free (pa_ang.d);
  plane_free (&mag);
  plane_free (&ang);
  plane_free (&resp);
  return f;
}

void
rts5812_features_free (Rts5812Features *f)
{
  if (!f)
    return;
  g_free (f->pts);
  g_free (f->desc);
  g_free (f);
}

int
rts5812_features_count (const Rts5812Features *f)
{
  return f->n;
}

/* xorshift32: fixed seed per call, so a given pair always scores the same. */
static inline guint32
xs32 (guint32 *s)
{
  *s ^= *s << 13;
  *s ^= *s >> 17;
  *s ^= *s << 5;
  return *s;
}

typedef struct
{
  int     n;
  float  *pa, *pb;   /* n matched point pairs, a-side and b-side */
} Matches;

/* Ratio-test matches from a's keypoints into b's, read off the distance table
 * D (a->n x b->n, row-major; transposed when `swap`, i.e. matching b into a). */
static void
ratio_matches (const Rts5812Features *a, const Rts5812Features *b,
               const guint32 *D, gboolean swap, Matches *m)
{
  const int na = swap ? b->n : a->n, nb = swap ? a->n : b->n;
  const Rts5812Features *fa = swap ? b : a, *fb = swap ? a : b;

  m->n = 0;
  m->pa = g_new (float, 2 * MAX (na, 1));
  m->pb = g_new (float, 2 * MAX (na, 1));
  for (int i = 0; i < na; i++)
    {
      guint32 d0 = G_MAXUINT32, d1 = G_MAXUINT32;
      int j0 = -1;

      for (int j = 0; j < nb; j++)
        {
          guint32 dist = swap ? D[(gsize) j * b->n + i] : D[(gsize) i * b->n + j];
          if (dist < d0)
            {
              d1 = d0;
              d0 = dist;
              j0 = j;
            }
          else if (dist < d1)
            {
              d1 = dist;
            }
        }
      if ((double) d0 < RTS5812_RATIO * RTS5812_RATIO * (double) d1)
        {
          m->pa[2 * m->n] = fa->pts[2 * i];
          m->pa[2 * m->n + 1] = fa->pts[2 * i + 1];
          m->pb[2 * m->n] = fb->pts[2 * j0];
          m->pb[2 * m->n + 1] = fb->pts[2 * j0 + 1];
          m->n++;
        }
    }
}

/* Largest set of matches consistent with one rotation + translation. */
static int
rigid_ransac (const Matches *m)
{
  const float *pa = m->pa, *pb = m->pb;
  const int n = m->n;
  int best = 0;
  guint32 seed = 0x5812u;

  if (n < 2)
    return 0;
  for (int it = 0; it < RTS5812_RANSAC_ITERS; it++)
    {
      int i = xs32 (&seed) % n, j = xs32 (&seed) % n;
      float vax, vay, vbx, vby, la, lb, t, c, s, tx, ty;
      int inl = 0;

      if (i == j)
        continue;
      vax = pa[2 * j] - pa[2 * i];
      vay = pa[2 * j + 1] - pa[2 * i + 1];
      vbx = pb[2 * j] - pb[2 * i];
      vby = pb[2 * j + 1] - pb[2 * i + 1];
      la = hypotf (vax, vay);
      lb = hypotf (vbx, vby);
      if (la < 3 || fabsf (la - lb) > 0.1f * la)
        continue;
      t = atan2f (vby, vbx) - atan2f (vay, vax);
      c = cosf (t);
      s = sinf (t);
      tx = pb[2 * i] - (c * pa[2 * i] - s * pa[2 * i + 1]);
      ty = pb[2 * i + 1] - (s * pa[2 * i] + c * pa[2 * i + 1]);
      for (int k = 0; k < n; k++)
        {
          float ex = c * pa[2 * k] - s * pa[2 * k + 1] + tx - pb[2 * k];
          float ey = s * pa[2 * k] + c * pa[2 * k + 1] + ty - pb[2 * k + 1];
          if (ex * ex + ey * ey < RTS5812_RANSAC_TOL * RTS5812_RANSAC_TOL)
            inl++;
        }
      best = MAX (best, inl);
    }
  return best;
}

int
rts5812_features_match (const Rts5812Features *a, const Rts5812Features *b)
{
  g_autofree guint32 *D = NULL;
  Matches m;
  int best;

  if (a->n < 2 || b->n < 2)
    return 0;

  /* squared descriptor distances, computed once for both directions */
  D = g_new (guint32, (gsize) a->n * b->n);
  for (int i = 0; i < a->n; i++)
    {
      const guint8 *da = a->desc + (gsize) i * RTS5812_DESC_LEN;
      for (int j = 0; j < b->n; j++)
        {
          const guint8 *db = b->desc + (gsize) j * RTS5812_DESC_LEN;
          guint32 dist = 0;
          for (int t = 0; t < RTS5812_DESC_LEN; t++)
            {
              int e = (int) da[t] - (int) db[t];
              dist += (guint32) (e * e);
            }
          D[(gsize) i * b->n + j] = dist;
        }
    }

  ratio_matches (a, b, D, FALSE, &m);
  best = rigid_ransac (&m);
  g_free (m.pa);
  g_free (m.pb);
  ratio_matches (a, b, D, TRUE, &m);
  best = MAX (best, rigid_ransac (&m));
  g_free (m.pa);
  g_free (m.pb);
  return best;
}
