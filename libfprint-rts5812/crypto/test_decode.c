/* test_decode.c — offline regression test for rts5812_crypto.
 *
 * Decodes the hardware-captured frame (../../frame.bin + ../../frame.bin.blob),
 * checks the derived session keys and CMAC against the known-good values, and
 * writes the decrypted fingerprint to a PGM. No device or libfprint needed.
 *
 *   make && ./test_decode ../../frame.bin ../../frame.bin.blob out.pgm
 */
#include "rts5812_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Known-good values from the verified Python decode (regression anchors).
 * Anchored to the committed frame.bin (Fedora run #5, SID fc3b5c3c…); these are
 * the per-session keys the probe logged and that CMAC-verify against that frame. */
static const char *EXP_CMAC_KEY =
  "0034c2eea34f276e015381f0b993e3db0e35faa39559d218316b34a22fe2d567";
static const char *EXP_CTR_KEY =
  "fd09949600417499e29a3ef13f7b04d6de2f43b5914ac5404084a77fd6ac49c2";

static uint8_t *read_file(const char *path, size_t *len)
{
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); return NULL; }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *buf = malloc(n);
  if (fread(buf, 1, n, f) != (size_t) n) { fclose(f); free(buf); return NULL; }
  fclose(f);
  *len = (size_t) n;
  return buf;
}

static void hex(const uint8_t *b, size_t n, char *out)
{
  for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

int main(int argc, char **argv)
{
  if (argc < 3) {
    fprintf(stderr, "usage: %s FRAME.bin FRAME.bin.blob [out.pgm]\n", argv[0]);
    return 2;
  }
  size_t frame_len, blob_len;
  uint8_t *frame = read_file(argv[1], &frame_len);
  uint8_t *blob = read_file(argv[2], &blob_len);
  if (!frame || !blob) return 2;

  if (blob_len < RTS5812_MASTER_KEY_OFF + RTS5812_KEY_LEN) {
    fprintf(stderr, "blob too short (%zu bytes)\n", blob_len);
    return 2;
  }
  const uint8_t *K = blob + RTS5812_MASTER_KEY_OFF;

  int fails = 0;
  char buf[96];

  /* 1. key derivation */
  uint8_t cmac_key[32], ctr_key[32];
  rts5812_derive_session_keys(K, frame + RTS5812_SID_OFF, cmac_key, ctr_key);
  hex(cmac_key, 32, buf);
  printf("cmac_key %s %s\n", buf, strcmp(buf, EXP_CMAC_KEY) ? "FAIL" : "ok");
  fails += strcmp(buf, EXP_CMAC_KEY) != 0;
  hex(ctr_key, 32, buf);
  printf("ctr_key  %s %s\n", buf, strcmp(buf, EXP_CTR_KEY) ? "FAIL" : "ok");
  fails += strcmp(buf, EXP_CTR_KEY) != 0;

  /* 2. verify + decrypt */
  uint8_t img[RTS5812_IMG_SIZE];
  int rc = rts5812_decode_frame(frame, frame_len, K, img);
  printf("decode   rc=%d %s\n", rc, rc == 0 ? "ok (CMAC VERIFIED)" : "FAIL");
  fails += rc != 0;

  if (rc == 0 && argc > 3) {
    FILE *f = fopen(argv[3], "wb");
    if (f) {
      fprintf(f, "P5\n%d %d\n255\n", RTS5812_IMG_W, RTS5812_IMG_H);
      fwrite(img, 1, RTS5812_IMG_SIZE, f);
      fclose(f);
      printf("wrote    %s (%dx%d)\n", argv[3], RTS5812_IMG_W, RTS5812_IMG_H);
    }
  }

  free(frame);
  free(blob);
  printf("%s\n", fails ? "RESULT: FAIL" : "RESULT: PASS");
  return fails ? 1 : 0;
}
