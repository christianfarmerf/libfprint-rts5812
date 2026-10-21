/* rts5812_crypto.h — RTS5812/TCFS2000 frame crypto (verified against hardware).
 *
 * Self-contained, no libfprint dependency, so it can be unit-tested offline.
 * Implements the session KDF, AES-256-CMAC integrity check and AES-256-CBC
 * image decryption reverse-engineered from RtsWBDI.dll (see ../../PROTOCOL.md).
 *
 * Requires nettle >= 3.6 (for cmac_aes256).
 */
#ifndef RTS5812_CRYPTO_H
#define RTS5812_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* Frame geometry (bytes), from iid_VerifyAndDecrypt 0x1800c1140. */
#define RTS5812_FRAME_LEN      0x41A0  /* bytes of the 0x4200 transfer that are used   */
#define RTS5812_SID_OFF        0x00    /* 8-byte session id                            */
#define RTS5812_SID_LEN        8
#define RTS5812_COUNTER_OFF    0x0C    /* 4-byte big-endian replay counter             */
#define RTS5812_IV_OFF         0x10    /* 16-byte AES-CBC IV                           */
#define RTS5812_CT_OFF         0x20    /* ciphertext start                             */
#define RTS5812_CMAC_OFF       0x4190  /* 16-byte AES-256-CMAC tag                      */
#define RTS5812_CT_LEN         (RTS5812_CMAC_OFF - RTS5812_CT_OFF)  /* 0x4170 */
#define RTS5812_TAG_LEN        16

/* Master key location inside the 948-byte "TCFS" device-key blob. */
#define RTS5812_KEYBLOB_LEN    0x3B4
#define RTS5812_MASTER_KEY_OFF 0x1C
#define RTS5812_KEY_LEN        32

/* Plaintext image geometry (saveImage2PGM 0x1800b8ee0). */
#define RTS5812_IMG_OFF        0x20B4  /* offset within the decrypted body */
#define RTS5812_IMG_W          135
#define RTS5812_IMG_H          62
#define RTS5812_IMG_SIZE       (RTS5812_IMG_W * RTS5812_IMG_H)  /* 8370 */

/* Derive cmac_key and ctr_key (each 32 bytes) from the 32-byte master key K and
 * the 8-byte session id, per the SP800-108-style KDF (FUN_1800c1c00). */
void rts5812_derive_session_keys(const uint8_t master_key[RTS5812_KEY_LEN],
                                 const uint8_t sid[RTS5812_SID_LEN],
                                 uint8_t cmac_key[RTS5812_KEY_LEN],
                                 uint8_t ctr_key[RTS5812_KEY_LEN]);

/* Expected inv_fp_open_session response: AES-256-CMAC over (SID || 0^8) with
 * cmac_key = KDF(mode=2, SID, K). The sensor's 16-byte reply must equal this
 * (iid_VerifySessionOpen 0x1800c13e0). out receives RTS5812_TAG_LEN bytes. */
void rts5812_session_oracle(const uint8_t master_key[RTS5812_KEY_LEN],
                            const uint8_t sid[RTS5812_SID_LEN],
                            uint8_t out[RTS5812_TAG_LEN]);

/* Verify + decrypt one frame.
 *   frame      : at least RTS5812_FRAME_LEN bytes as read from getImageData
 *   master_key : K = keyblob[0x1C:0x3C]
 *   out_img    : receives RTS5812_IMG_SIZE grayscale pixels
 * Returns 0 on success (CMAC verified), -1 on bad args/length, -2 on CMAC
 * mismatch (keys or frame wrong; out_img is left untouched).
 */
int rts5812_decode_frame(const uint8_t *frame, size_t frame_len,
                         const uint8_t master_key[RTS5812_KEY_LEN],
                         uint8_t out_img[RTS5812_IMG_SIZE]);

#endif /* RTS5812_CRYPTO_H */
