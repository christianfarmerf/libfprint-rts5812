/* rts5812_match.h — keypoint matcher for the RTS5812's small (135x62) frames.
 *
 * NBIS minutiae matching does not work on this sensor: a frame covers ~7x3 mm of
 * finger and holds only ~4-5 real minutiae. Instead each frame is reduced to a
 * few hundred local ridge keypoints with SIFT-like descriptors, and two frames
 * are compared by the number of keypoint matches that agree on a single rigid
 * motion (2-point RANSAC). Different fingers top out at ~6-7 inliers; frames of
 * the same finger that physically overlap score 10-100.
 *
 * Plain C + glib only, so it builds both inside libfprint and in the offline
 * test harness (test_match.c). */
#ifndef RTS5812_MATCH_H
#define RTS5812_MATCH_H

#include <glib.h>

/* Inlier count at or above which two frames are taken to be the same finger.
 * On dataset2 (30 frames, 3 fingers) different fingers top out at 5 inliers,
 * even taking the best of 10 enrolled frames; on hardware (2 px tolerance, 12
 * frames) at 7. Genuine overlapping presses score 8-42 on hardware. */
#define RTS5812_MATCH_THRESHOLD 8

typedef struct _Rts5812Features Rts5812Features;

/* Extract keypoints + descriptors from a raw (un-normalized) w x h 8-bit frame. */
Rts5812Features *rts5812_features_extract (const guint8 *img, int w, int h);
void             rts5812_features_free (Rts5812Features *f);
int              rts5812_features_count (const Rts5812Features *f);

/* Symmetric match score: max rigid-RANSAC inlier count over both directions. */
int rts5812_features_match (const Rts5812Features *a, const Rts5812Features *b);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (Rts5812Features, rts5812_features_free)

#endif /* RTS5812_MATCH_H */
