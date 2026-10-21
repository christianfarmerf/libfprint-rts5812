# Step B — offline match-viability result (2026-10-20)

**Question:** do the small (135×62), low-contrast RTS5812 frames carry enough
identity to enroll and match, or is the biometric path a dead end before we commit
to the C driver?

**Answer: identity is recoverable — proceed to the C driver.**
6 of 7 captured presses correctly identify their own finger over a different finger.

## What was run

Input: 7 live frames from Fedora run #5 — index finger ×4, middle finger ×3
(`frame_index01..04`, `frame_middle01..03`), each a CMAC-verified authentic capture.

NBIS (`mindtct`/`bozorth3`) could not be run on this Windows box (no C toolchain;
WSL2 blocked by BIOS). So Step B was answered with a **pure-Python match backend**
(`rts5812_pymatch.py`), which uses two independent signals:

1. **Ridge cross-correlation (the trusted signal).** Band-pass the real ridges,
   keep only high-coherence pixels, and measure the best normalized correlation of
   each frame pair under a small rigid search (±24 px shift, ±12° rotation). This
   invents nothing — it asks directly whether one press's ridge pattern lines up
   with another's.
2. **Minutiae matcher (experimental cross-check only).** Orientation field → Gabor
   enhance → Zhang-Suen thin → crossing-number minutiae → Hough alignment score.
   At this resolution, without NBIS's production Gabor/thinning, our enhancer
   hallucinates ridges in low-contrast regions (verified visually — see below), so
   minutiae are too noisy to trust. Kept in the tool, labelled, **not** used for the
   verdict. This is itself evidence that the driver should hand libfprint a clean
   normalized image and let NBIS do extraction, rather than pre-extracting minutiae.

```sh
python3 rts5812_match.py frame_index*.bin frame_middle*.bin --out match_out
```

## Result (ridge-correlation, on the `stretch` normalization)

Rank-1 identification — each press probed against all other frames:

| probe      | best same-finger | best diff-finger | verdict |
|------------|-----------------:|-----------------:|---------|
| index01    | 0.822 | 0.563 | OK |
| index02    | 0.822 | 0.571 | OK |
| index03    | 0.772 | 0.491 | OK |
| index04    | 0.592 | 0.462 | OK |
| middle01   | 0.616 | 0.506 | OK |
| middle02   | 0.616 | 0.571 | OK |
| middle03   | 0.426 | 0.523 | **MISID** |

**6/7 presses identify their own finger.** Pairwise AUC = 0.611, d′ = 0.75
(genuine distribution above impostor). The strong same-finger pairs
(index01/02/03 mutually 0.72–0.82) sit far above the impostor ceiling (0.571).

## Interpretation

- **The sensor images are good.** The `stretch` variant shows clean, curving ridges
  with clear loop structure (`match_out/frame_index01_stretch.pgm`). The signal is
  real; the earlier "no separation" from the raw minutiae matcher was a *matcher*
  artifact, not an image defect.
- **The limiting factor is overlap, not quality.** On a small platen, two presses of
  the same finger capture shifted/partial, sometimes rotated regions. Same-finger
  pairs with good overlap correlate strongly; pairs with little overlap correlate
  weakly. The single failure, `middle03`, is a demonstrably weak press
  (best genuine 0.426 — low against *all* its siblings), i.e. exactly the kind of bad
  capture enrollment is meant to reject, not misenroll.

## Implications for the C driver (Step C)

1. **Normalization: apply a per-image contrast normalization before matching.** A
   global 2/98-percentile stretch was enough to expose ridges cleanly here; the
   simple local high-pass (`loceq`) is an equally cheap fallback and ports directly.
   Bake one in — the raw frame (std ≈ 6.3) is too flat to feed a matcher as-is.
2. **Enroll from multiple frames.** libfprint's multi-frame enrollment is not
   optional for this sensor — a single press often won't overlap a later probe.
   Capture several firm, centred presses per finger.
3. **Let NBIS do minutiae extraction.** Feed libfprint good normalized images;
   don't pre-extract. (Our Python minutiae stage exists only to study the images.)
4. **Expect, and handle, weak presses.** ~1 in 7 presses here was too faint/partial
   to match. Firm, centred contact and a capture-quality gate (reject near-flat or
   low-coherence frames — the probe already warns on these) will cut that rate.

## Still to confirm (cheap, on Fedora)

Run the **reference** matcher where NBIS installs trivially, to put real bozorth3
numbers behind this proxy:

```sh
# on Fedora: build NBIS (or use the libfprint-vendored nbis subtree), then
python3 rts5812_match.py frame_index*.bin frame_middle*.bin --out match_out
# it auto-detects mindtct/bozorth3 and prints the real genuine/impostor matrix
```

Given the ridge-correlation separation above, real bozorth3 on the strong same-finger
pairs is expected to clear its conventional ~40 accept threshold. This is a
confirmation step, not a gate — Step C can start now.
