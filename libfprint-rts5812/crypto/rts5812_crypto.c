/* rts5812_crypto.c — see rts5812_crypto.h.
 *
 * Crypto, byte-for-byte as reversed from RtsWBDI.dll and verified against a
 * real captured frame (CMAC tag reproduced exactly; CBC yields the image):
 *
 *   K        = keyblob[0x1C:0x3C]                       (32 bytes, AES-256)
 *   SID      = frame[0x00:0x08]
 *   KDF(mode): out = CMAC_K(block0) || CMAC_K(block1),  where
 *              block(i) = 00 i mode 00 | SID[0:8] | 00 00 01 00   (16 bytes)
 *   cmac_key = KDF(mode=2) ;  ctr_key = KDF(mode=1)
 *   tag check: AES256_CMAC_{cmac_key}(frame[0x0000:0x4190]) == frame[0x4190:0x41A0]
 *   body     : AES256_CBC_decrypt(frame[0x20:0x4190], IV=frame[0x10:0x20], ctr_key)
 *
 * The body cipher is CBC (not CTR); see the 2026-10-19 correction in PROTOCOL.md.
 */
#include "rts5812_crypto.h"

#include <string.h>
#include <nettle/aes.h>
#include <nettle/cbc.h>
#include <nettle/cmac.h>
#include <nettle/memops.h>   /* memeql_sec */

static void
kdf_one(const uint8_t master_key[RTS5812_KEY_LEN],
        const uint8_t sid[RTS5812_SID_LEN],
        uint8_t mode,
        uint8_t out[RTS5812_KEY_LEN])
{
  struct cmac_aes256_ctx ctx;
  cmac_aes256_set_key(&ctx, master_key);

  for (uint8_t i = 0; i < 2; i++)
    {
      uint8_t block[16];
      block[0] = 0x00;
      block[1] = i;
      block[2] = mode;
      block[3] = 0x00;
      memcpy(block + 4, sid, RTS5812_SID_LEN); /* bytes 4..11 */
      block[12] = 0x00;
      block[13] = 0x00;
      block[14] = 0x01;
      block[15] = 0x00;

      /* cmac_aes256_update keeps state across calls, so re-set the key each
       * block to get an independent one-block MAC. */
      cmac_aes256_set_key(&ctx, master_key);
      cmac_aes256_update(&ctx, sizeof block, block);
      cmac_aes256_digest(&ctx, 16, out + (size_t) i * 16);
    }
}

void
rts5812_derive_session_keys(const uint8_t master_key[RTS5812_KEY_LEN],
                            const uint8_t sid[RTS5812_SID_LEN],
                            uint8_t cmac_key[RTS5812_KEY_LEN],
                            uint8_t ctr_key[RTS5812_KEY_LEN])
{
  kdf_one(master_key, sid, 2, cmac_key);
  kdf_one(master_key, sid, 1, ctr_key);
}

void
rts5812_session_oracle(const uint8_t master_key[RTS5812_KEY_LEN],
                       const uint8_t sid[RTS5812_SID_LEN],
                       uint8_t out[RTS5812_TAG_LEN])
{
  uint8_t cmac_key[RTS5812_KEY_LEN];
  kdf_one(master_key, sid, 2, cmac_key);

  /* message = SID padded with zeros to one AES block */
  uint8_t msg[16];
  memset(msg, 0, sizeof msg);
  memcpy(msg, sid, RTS5812_SID_LEN);

  struct cmac_aes256_ctx mac;
  cmac_aes256_set_key(&mac, cmac_key);
  cmac_aes256_update(&mac, sizeof msg, msg);
  cmac_aes256_digest(&mac, RTS5812_TAG_LEN, out);
}

int
rts5812_decode_frame(const uint8_t *frame, size_t frame_len,
                     const uint8_t master_key[RTS5812_KEY_LEN],
                     uint8_t out_img[RTS5812_IMG_SIZE])
{
  if (!frame || !master_key || !out_img || frame_len < RTS5812_FRAME_LEN)
    return -1;

  const uint8_t *sid = frame + RTS5812_SID_OFF;
  const uint8_t *iv_in = frame + RTS5812_IV_OFF;
  const uint8_t *ct = frame + RTS5812_CT_OFF;
  const uint8_t *tag = frame + RTS5812_CMAC_OFF;

  uint8_t cmac_key[RTS5812_KEY_LEN];
  uint8_t ctr_key[RTS5812_KEY_LEN];
  rts5812_derive_session_keys(master_key, sid, cmac_key, ctr_key);

  /* Integrity: AES-256-CMAC over frame[0x0000 .. 0x4190) with cmac_key. */
  struct cmac_aes256_ctx mac;
  uint8_t calc_tag[RTS5812_TAG_LEN];
  cmac_aes256_set_key(&mac, cmac_key);
  cmac_aes256_update(&mac, RTS5812_CMAC_OFF, frame);
  cmac_aes256_digest(&mac, sizeof calc_tag, calc_tag);

  if (!memeql_sec(calc_tag, tag, RTS5812_TAG_LEN))
    return -2;

  /* Body: AES-256-CBC decrypt. cbc_decrypt mutates the IV buffer in place. */
  struct aes256_ctx aes;
  uint8_t iv[16];
  uint8_t body[RTS5812_CT_LEN];
  aes256_set_decrypt_key(&aes, ctr_key);
  memcpy(iv, iv_in, sizeof iv);
  cbc_decrypt(&aes, (nettle_cipher_func *) aes256_decrypt, AES_BLOCK_SIZE,
              iv, RTS5812_CT_LEN, body, ct);

  memcpy(out_img, body + RTS5812_IMG_OFF, RTS5812_IMG_SIZE);
  return 0;
}
