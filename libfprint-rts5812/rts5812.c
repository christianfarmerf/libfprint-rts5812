/*
 * Realtek RTS5812 + TDK TCFS2000 fingerprint driver for libfprint.
 *
 * FpDevice driver with host-side matching: the sensor delivers an encrypted
 * 135x62 grayscale frame which, once the session keys are derived, decrypts to
 * an image. libfprint's NBIS pipeline cannot match these: the frame covers only
 * ~7x3 mm of finger (~4-5 real minutiae). Instead enrollment stores several raw
 * frames in the print, and verify/identify compare a new frame against them
 * with the keypoint + rigid-RANSAC matcher in rts5812_match.c.
 *
 * The protocol was reverse-engineered from RtsWBDI.dll (see ../PROTOCOL.md)
 * and every stage below is hardware-proven by the Python reference probe
 * (../rts5812_probe.py, Fedora runs #4/#5): USB transport + framing, DMP firmware
 * upload, mode bring-up (1/14/5), the responder arm (inv_fp_start), the session
 * handshake (inv_fp_open_session), capture, and the frame crypto. This C port
 * mirrors that probe step for step. The one thing that cannot be exercised on the
 * dev box (Windows, no libfprint) is this file compiling+running inside a libfprint
 * tree -- do that pass on the Linux machine; the logic is a faithful 1:1 port.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "rts5812"

#include <string.h>
#include <sys/random.h>            /* getrandom() for the session id          */

#include "drivers_api.h"            /* libfprint internal driver API           */
#include "rts5812.h"
#include "rts5812_fw.h"             /* embedded DMP firmware (rts5812_dmp_fw)   */
#include "crypto/rts5812_crypto.h"
#include "rts5812_match.h"

struct _FpiDeviceRts5812
{
  FpDevice      parent;

  FpiSsm       *ssm;
  guint8        ep_in;
  guint8        ep_out;

  guint8        master_key[RTS5812_KEY_LEN];                 /* K = blob[0x1C:0x3C]  */
  guint8        start_material[RTS5812_START_BLOB_LEN];      /* blob[0x3C:0x3B4]     */
  gboolean      have_key;

  guint8        sid[RTS5812_SID_LEN];                        /* current session id   */
  gboolean      session_open;

  guint         poll_count;

  guint8        status;                     /* last getImageStatus result       */
  gboolean      fresh_open;                 /* no capture armed since dev_open  */
  guint8       *xfer;                       /* getImageData buffer              */
  guint8        frame[RTS5812_IMG_SIZE];    /* last decoded raw frame           */
  GPtrArray    *enroll_frames;              /* GBytes, accepted enroll frames   */
  GError       *capture_error;              /* deferred result for capture()    */
  GHashTable   *feature_cache;              /* GBytes frame -> Rts5812Features  */
  FpImage      *capture_image;
};
G_DECLARE_FINAL_TYPE (FpiDeviceRts5812, fpi_device_rts5812, FPI,
                      DEVICE_RTS5812, FpDevice)
G_DEFINE_TYPE (FpiDeviceRts5812, fpi_device_rts5812, FP_TYPE_DEVICE)

/* ------------------------------------------------------------------ */
/* Low-level command framing                                           */
/* ------------------------------------------------------------------ */

/* Build and send the 8-byte command header, do the data phase, read the
 * 5-byte status. Synchronous: bring-up and the session handshake run in dev_open,
 * where a blocking sequence is acceptable. Never call it while an action is in
 * progress: see rts5812_cmd_async() for why the capture path must not.
 * Returns TRUE on success, with *data_in filled for read ops.
 */
static gboolean
rts5812_cmd (FpiDeviceRts5812 *self, guint8 op, guint8 reg,
             const guint8 *data_out, guint8 *data_in, guint16 len,
             GError **error)
{
  FpDevice *dev = FP_DEVICE (self);
  guint8 header[RTS5812_HDR_LEN] = {
    RTS5812_HDR_MAGIC, op, 0x00, 0x00, reg, 0x00,
    (guint8) (len & 0xff), (guint8) (len >> 8)
  };
  g_autoptr(FpiUsbTransfer) t = NULL;
  /* fpi_usb_transfer_submit_sync() dereferences *error unconditionally
   * (log_transfer(transfer, FALSE, *error)), so it must never be handed a NULL
   * error pointer. Substitute a local one for callers that don't want it. */
  g_autoptr(GError) local_error = NULL;
  if (!error)
    error = &local_error;

  /* Phase 1: header OUT */
  t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk_full (t, self->ep_out, header, sizeof header, NULL);
  if (!fpi_usb_transfer_submit_sync (t, RTS5812_USB_TIMEOUT_MS, error))
    return FALSE;
  g_clear_pointer (&t, fpi_usb_transfer_unref);

  /* Phase 2: data OUT (writes) or IN (reads) */
  if (len > 0)
    {
      gboolean is_read = (op == RTS5812_OP_READ_REG ||
                          op == RTS5812_OP_GET_IMAGE ||
                          op == RTS5812_OP_IMAGE_STATUS ||
                          op == RTS5812_OP_RETRIEVE_KEY);
      t = fpi_usb_transfer_new (dev);
      if (is_read)
        fpi_usb_transfer_fill_bulk (t, self->ep_in, len);
      else
        fpi_usb_transfer_fill_bulk_full (t, self->ep_out,
                                         (guint8 *) data_out, len, NULL);
      if (!fpi_usb_transfer_submit_sync (t, RTS5812_USB_TIMEOUT_MS, error))
        return FALSE;
      if (is_read && data_in)
        memcpy (data_in, t->buffer, len);
      g_clear_pointer (&t, fpi_usb_transfer_unref);
    }

  /* Phase 3: 5-byte status IN; byte 0 == 0 => success */
  t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (t, self->ep_in, RTS5812_STATUS_LEN);
  if (!fpi_usb_transfer_submit_sync (t, RTS5812_USB_TIMEOUT_MS, error))
    return FALSE;
  if (t->buffer[0] != 0x00)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "rts5812 command 0x%02x (reg 0x%02x) status error %d",
                   op, reg, t->buffer[0]);
      return FALSE;
    }
  return TRUE;
}

/* Register helpers. read_reg8(r) reads serial register r|0x80 (serial_read);
 * raw reads/writes pass the register through unchanged (DMP streams use 0x8C/0x0C
 * which already carry the right bits). */
static gboolean
rts5812_write_reg (FpiDeviceRts5812 *self, guint8 reg,
                   const guint8 *data, guint16 len, GError **e)
{
  return rts5812_cmd (self, RTS5812_OP_WRITE_REG, reg, data, NULL, len, e);
}

static gboolean
rts5812_read_reg (FpiDeviceRts5812 *self, guint8 reg,
                  guint8 *buf, guint16 len, GError **e)
{
  return rts5812_cmd (self, RTS5812_OP_READ_REG, reg, NULL, buf, len, e);
}

static gboolean
rts5812_write_reg8 (FpiDeviceRts5812 *self, guint8 reg, guint8 val, GError **e)
{
  return rts5812_write_reg (self, reg, &val, 1, e);
}

static gboolean
rts5812_read_reg8 (FpiDeviceRts5812 *self, guint8 reg, guint8 *val, GError **e)
{
  /* read_reg8(r) = serial_read(r | 0x80, 1)  (0x1800ba7a8) */
  return rts5812_read_reg (self, reg | 0x80, val, 1, e);
}

/* ------------------------------------------------------------------ */
/* DMP memory + idle polling                                           */
/* ------------------------------------------------------------------ */

/* write_dmp_mem (0x1800ba43c): set the 4-byte LE pointer in reg 0x08, then stream
 * data into reg 0x0C. The pointer auto-advances, so large buffers are chunked to
 * one bulk packet minus a byte (the bridge stalls on larger register writes). */
static gboolean
rts5812_write_dmp_mem (FpiDeviceRts5812 *self, guint32 addr,
                       const guint8 *data, gsize len, GError **e)
{
  guint8 a[4] = { addr & 0xff, (addr >> 8) & 0xff,
                  (addr >> 16) & 0xff, (addr >> 24) & 0xff };
  if (!rts5812_write_reg (self, RTS5812_REG_DMP_ADDR, a, sizeof a, e))
    return FALSE;
  for (gsize off = 0; off < len; off += RTS5812_DMP_CHUNK)
    {
      guint16 chunk = MIN ((gsize) RTS5812_DMP_CHUNK, len - off);
      if (!rts5812_write_reg (self, RTS5812_REG_DMP_WRITE, data + off, chunk, e))
        return FALSE;
    }
  return TRUE;
}

/* wait_dmp_idle (0x1800ba89c): poll reg 0x0E; idle iff (v & 6) == 2. Optionally
 * returns the final status byte (callers inspect bits 0x08/0x20/0x40). */
static gboolean
rts5812_wait_dmp_idle (FpiDeviceRts5812 *self, guint8 *out_v, GError **e)
{
  guint8 v = 0;
  for (int i = 0; i < 100; i++)
    {
      if (!rts5812_read_reg8 (self, RTS5812_REG_DMP_STATUS, &v, e))
        return FALSE;
      if ((v & 5) != 1)
        break;
      g_usleep (1000);
    }
  if (v & RTS5812_DMP_BIT_BUSY)
    {
      g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "wait_dmp_idle: DMP busy (0x0E=0x%02x)", v);
      return FALSE;
    }
  if ((v & 6) != RTS5812_DMP_BIT_IDLE)
    {
      g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "wait_dmp_idle: not idle (0x0E=0x%02x)", v);
      return FALSE;
    }
  if (out_v)
    *out_v = v;
  return TRUE;
}

/* ------------------------------------------------------------------ */
/* Sensor bring-up primitives (setupDevice layer, PROTOCOL.md)         */
/* ------------------------------------------------------------------ */

static gboolean
rts5812_hardware_reset (FpiDeviceRts5812 *self, GError **e)
{
  /* 0x1800ba118: w(0x3A,0x02); 2ms; w(0x04,0x3F); 1ms. */
  if (!rts5812_write_reg8 (self, 0x3A, 0x02, e)) return FALSE;
  g_usleep (2000);
  if (!rts5812_write_reg8 (self, 0x04, 0x3F, e)) return FALSE;
  g_usleep (1000);
  return TRUE;
}

static gboolean
rts5812_lp_mode_set (FpiDeviceRts5812 *self, gboolean enable, GError **e)
{
  /* 0x1800ba2fc: w(0x01, en?1:0); when waking, wait for r(0x39) bit1. */
  if (!rts5812_write_reg8 (self, 0x01, enable ? 1 : 0, e))
    return FALSE;
  if (enable)
    return TRUE;
  g_usleep (5000);
  for (int i = 0; i < 10; i++)
    {
      guint8 v;
      if (!rts5812_read_reg8 (self, 0x39, &v, e)) return FALSE;
      if (v & 0x02) return TRUE;
      g_usleep (1000);
    }
  g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "lp_mode_set(0): r(0x39) bit1 never set");
  return FALSE;
}

static gboolean
rts5812_dmp_halt (FpiDeviceRts5812 *self, GError **e)
{
  /* 0x1800ba0c8: loop until r(0x39)&4; kick with w(0x04,0x20). */
  for (int i = 0; i < 1000; i++)
    {
      guint8 v;
      if (!rts5812_read_reg8 (self, 0x39, &v, e)) return FALSE;
      if (v & 0x04) return TRUE;
      if (!rts5812_write_reg8 (self, 0x04, 0x20, e)) return FALSE;
    }
  g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "dmp_halt: r(0x39) bit2 never set");
  return FALSE;
}

static gboolean
rts5812_wait_irq (FpiDeviceRts5812 *self, GError **e)
{
  /* 0x1800ba908: poll r(0x03)==1, 1ms apart, up to 500 tries. */
  for (int i = 0; i < 500; i++)
    {
      guint8 v;
      if (!rts5812_read_reg8 (self, 0x03, &v, e)) return FALSE;
      if (v == 1) return TRUE;
      g_usleep (1000);
    }
  g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "wait_irq: r(0x03) never == 1");
  return FALSE;
}

static gboolean
rts5812_dmp_start (FpiDeviceRts5812 *self, GError **e)
{
  /* 0x1800b9ff8: fixed register program that starts the DMP core. */
  static const guint8 prog[][2] = {
    { 0x1B, 0x60 }, { 0x10, 0x00 }, { 0x11, 0x00 }, { 0x12, 0x01 },
    { 0x14, 0x04 }, { 0x15, 0x00 }, { 0x16, 0x01 }, { 0x18, 0x08 },
    { 0x19, 0x00 }, { 0x1A, 0x01 }, { 0x7C, 0x01 },
  };
  for (gsize i = 0; i < G_N_ELEMENTS (prog); i++)
    if (!rts5812_write_reg8 (self, prog[i][0], prog[i][1], e))
      return FALSE;
  return TRUE;
}

static gboolean
rts5812_load_dmp_firmware (FpiDeviceRts5812 *self, GError **e)
{
  /* 0x1800ba190: w(0x04,0x01); upload fw to DMP 0x10000; read back + verify;
   * dmp_start; w(0x3E,0x04). The read-back is skipped: it was advisory only
   * (a mismatch merely logged), it doubled the ~0.4 s upload that fprintd pays
   * on every claim, and a bad upload still fails loudly at the verified
   * session handshake that follows bring-up. */
  if (!rts5812_write_reg8 (self, 0x04, 0x01, e))
    return FALSE;
  if (!rts5812_write_dmp_mem (self, RTS5812_DMP_FW_ADDR,
                              rts5812_dmp_fw, rts5812_dmp_fw_len, e))
    return FALSE;
  fp_dbg ("rts5812: firmware uploaded (%zu bytes)", rts5812_dmp_fw_len);

  if (!rts5812_dmp_start (self, e))
    return FALSE;
  return rts5812_write_reg8 (self, 0x3E, 0x04, e);
}

static gboolean
rts5812_bypass_gain_comp_enable (FpiDeviceRts5812 *self, gboolean enable, GError **e)
{
  /* 0x1800b9d64: dmp[0x16AAF] = en ? 3 : 0. */
  guint8 b = enable ? 3 : 0;
  return rts5812_write_dmp_mem (self, RTS5812_DMP_GAINCOMP_ADDR, &b, 1, e);
}

static gboolean
rts5812_apply_custom_generator (FpiDeviceRts5812 *self, GError **e)
{
  /* 0x1800b8ac8: dmp[0x16E18] = 0x0000005A (LE32); runs just before mode 5. */
  static const guint8 cg[4] = { 0x5A, 0x00, 0x00, 0x00 };
  return rts5812_write_dmp_mem (self, RTS5812_DMP_CUSTGEN_ADDR, cg, sizeof cg, e);
}

static gboolean
rts5812_change_mode_simple (FpiDeviceRts5812 *self, guint8 mode, GError **e)
{
  /* 0x1800b9d8c: halt; idle; w(0x1D,mode); modes 5/12/20 also clear 0x55. */
  if (!rts5812_dmp_halt (self, e)) return FALSE;
  if (!rts5812_wait_dmp_idle (self, NULL, e)) return FALSE;
  if (!rts5812_write_reg8 (self, 0x1D, mode, e)) return FALSE;
  if (mode == 5 || mode == 12 || mode == 20)
    if (!rts5812_write_reg8 (self, 0x55, 0, e)) return FALSE;
  return TRUE;
}

static gboolean
rts5812_change_dmp_mode (FpiDeviceRts5812 *self, guint8 mode, GError **e)
{
  /* change_dmp_mode_with_completion (0x1800b9df0). */
  if (mode == 5 || mode == 12 || mode == 20)
    {
      guint8 r55;
      if (!rts5812_write_reg8 (self, 0x1D, mode, e)) return FALSE;
      if (!rts5812_wait_irq (self, e)) return FALSE;
      if (!rts5812_read_reg8 (self, 0x55, &r55, e)) return FALSE;
      if (r55 == 1)
        {
          if (!rts5812_dmp_halt (self, e)) return FALSE;
          if (!rts5812_write_reg8 (self, 0x55, 0, e)) return FALSE;
          if (!rts5812_wait_irq (self, e)) return FALSE;
        }
      return rts5812_wait_dmp_idle (self, NULL, e);
    }
  if (!rts5812_change_mode_simple (self, mode, e)) return FALSE;
  return rts5812_wait_irq (self, e);
}

/* ------------------------------------------------------------------ */
/* Security session: inv_fp_start + inv_fp_open_session                */
/* ------------------------------------------------------------------ */

static gboolean
rts5812_wait_session_ready (FpiDeviceRts5812 *self, GError **e)
{
  /* FUN_1800ba960 -> FUN_1800ba15c: wait until (r(0x39) & 4) == 0, <=100ms. */
  for (int i = 0; i < 100; i++)
    {
      guint8 v;
      if (!rts5812_read_reg8 (self, RTS5812_REG_DMP_READY, &v, e)) return FALSE;
      if ((v & 0x04) == 0) return TRUE;
      g_usleep (1000);
    }
  g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "wait_session_ready: r(0x39) bit2 never cleared");
  return FALSE;
}

/* inv_fp_start (0x1800ba820): the securitySessionStart step that arms the on-chip
 * responder. Precondition (from the asm): wait_dmp_idle, then 0x0E bit 0x20 set
 * (the state modes 1/14/5 leave) -- or already serviceable. It replays the
 * 0x378-byte per-device start material into DMP address 0 and pokes reg 0x0D=4,
 * which is what flips 0x0E bit 0x08. */
static gboolean
rts5812_start_session (FpiDeviceRts5812 *self, GError **e)
{
  guint8 v;
  if (!rts5812_wait_dmp_idle (self, &v, e))
    return FALSE;
  if (!(v & RTS5812_DMP_BIT_MODE))
    {
      if ((v & 0x0A) == 0x0A)
        return TRUE;             /* responder already armed */
      g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "start_session: 0x0E=0x%02x not ready (bit0x20 clear)", v);
      return FALSE;
    }
  if (!rts5812_write_dmp_mem (self, RTS5812_START_DMP_ADDR,
                              self->start_material, RTS5812_START_BLOB_LEN, e))
    return FALSE;
  if (!rts5812_write_reg8 (self, RTS5812_REG_SESSION_TRIGGER,
                           RTS5812_SESSION_START_VAL, e))
    return FALSE;
  return rts5812_wait_dmp_idle (self, NULL, e);
}

/* inv_fp_open_session (0x1800ba4fc): write SID -> DMP 0x3D0, trigger w(0x0D,8),
 * wait, then read the 16-byte CMAC reply from reg 0x87. Requires the responder
 * armed (0x0E bit 0x08 set, 0x40 clear). resp receives RTS5812_TAG_LEN bytes. */
static gboolean
rts5812_open_session (FpiDeviceRts5812 *self, const guint8 sid[RTS5812_SID_LEN],
                      guint8 resp[RTS5812_TAG_LEN], GError **e)
{
  guint8 v;
  if (!rts5812_wait_dmp_idle (self, &v, e))
    return FALSE;
  if (!(v & RTS5812_DMP_BIT_ARMED))
    {
      g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "open_session: responder not armed (0x0E=0x%02x)", v);
      return FALSE;
    }
  if (v & RTS5812_DMP_BIT_BLOCK)
    {
      g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "open_session: 0x0E=0x%02x bit0x40 set", v);
      return FALSE;
    }
  if (!rts5812_write_dmp_mem (self, RTS5812_SID_DMP_ADDR, sid, RTS5812_SID_LEN, e))
    return FALSE;
  if (!rts5812_write_reg8 (self, RTS5812_REG_SESSION_TRIGGER,
                           RTS5812_SESSION_OPEN_VAL, e))
    return FALSE;
  if (!rts5812_wait_dmp_idle (self, NULL, e))
    return FALSE;
  if (!rts5812_wait_session_ready (self, e))
    return FALSE;
  return rts5812_read_reg (self, RTS5812_REG_SESSION_RESP, resp, RTS5812_TAG_LEN, e);
}

/* ------------------------------------------------------------------ */
/* Key blob + full bring-up orchestration                              */
/* ------------------------------------------------------------------ */

/* Retrieve the TCFS device-key blob and cache K (blob[0x1C:0x3C]) and the
 * per-device start material (blob[0x3C:0x3B4]). */
static gboolean
rts5812_load_keyblob (FpiDeviceRts5812 *self, GError **error)
{
  guint8 blob[RTS5812_KEYBLOB_LEN];
  if (!rts5812_cmd (self, RTS5812_OP_RETRIEVE_KEY, 0x00, NULL, blob,
                    sizeof blob, error))
    return FALSE;
  if (memcmp (blob, "TCFS", 4) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "device-key blob is not tagged TCFS");
      return FALSE;
    }
  memcpy (self->master_key, blob + RTS5812_MASTER_KEY_OFF, RTS5812_KEY_LEN);
  memcpy (self->start_material, blob + RTS5812_START_BLOB_OFF,
          RTS5812_START_BLOB_LEN);
  self->have_key = TRUE;
  return TRUE;
}

/* warm_dmp: the setupDevice bring-up that arms the session responder, from cold.
 * identity -> wake -> reset -> wake -> firmware upload -> gain-comp off ->
 * change_dmp_mode(1,14,5) (applyCustomGenerator before 5) -> inv_fp_start. */
static gboolean
rts5812_warm_dmp (FpiDeviceRts5812 *self, GError **e)
{
  static const guint8 modes[] = { RTS5812_MODE_1, RTS5812_MODE_14, RTS5812_MODE_5 };
  guint8 who, v;

  if (!rts5812_read_reg8 (self, RTS5812_REG_WHOAMI, &who, e)) return FALSE;
  if (who != RTS5812_WHOAMI_VAL)
    fp_warn ("rts5812: unexpected whoami 0x%02x during bring-up", who);

  if (!rts5812_lp_mode_set (self, FALSE, e)) return FALSE;
  if (!rts5812_hardware_reset (self, e)) return FALSE;
  if (!rts5812_lp_mode_set (self, FALSE, e)) return FALSE;
  if (!rts5812_load_dmp_firmware (self, e)) return FALSE;
  if (!rts5812_bypass_gain_comp_enable (self, FALSE, e)) return FALSE;

  for (gsize i = 0; i < G_N_ELEMENTS (modes); i++)
    {
      if (modes[i] == RTS5812_MODE_5 && !rts5812_apply_custom_generator (self, e))
        return FALSE;
      if (!rts5812_change_dmp_mode (self, modes[i], e))
        return FALSE;
    }

  if (!rts5812_start_session (self, e))
    return FALSE;

  if (!rts5812_read_reg8 (self, RTS5812_REG_DMP_STATUS, &v, e)) return FALSE;
  if (!(v & RTS5812_DMP_BIT_ARMED) || (v & RTS5812_DMP_BIT_BLOCK))
    {
      g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "bring-up finished but responder not armed (0x0E=0x%02x)", v);
      return FALSE;
    }
  fp_dbg ("rts5812: responder armed (0x0E=0x%02x)", v);
  return TRUE;
}

/* Open a fresh session: pick a random SID, run the handshake, and confirm the
 * sensor's reply against the auth oracle AES256_CMAC_{cmac_key}(SID||0^8). */
static gboolean
rts5812_open_session_verified (FpiDeviceRts5812 *self, GError **e)
{
  guint8 sid[RTS5812_SID_LEN];
  guint8 resp[RTS5812_TAG_LEN];
  guint8 oracle[RTS5812_TAG_LEN];

  if (getrandom (sid, sizeof sid, 0) != (gssize) sizeof sid)
    for (gsize i = 0; i < sizeof sid; i++)       /* fallback; SID need not be secret */
      sid[i] = (guint8) g_random_int ();

  if (!rts5812_open_session (self, sid, resp, e))
    return FALSE;

  rts5812_session_oracle (self->master_key, sid, oracle);
  if (memcmp (resp, oracle, RTS5812_TAG_LEN) != 0)
    {
      g_set_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "session open not confirmed (sensor reply != auth oracle)");
      return FALSE;
    }
  memcpy (self->sid, sid, sizeof sid);
  self->session_open = TRUE;
  fp_dbg ("rts5812: session open confirmed");
  return TRUE;
}

/* ------------------------------------------------------------------ */
/* Image normalization (Step B: these frames are too flat raw)         */
/* ------------------------------------------------------------------ */

/* A per-image 2/98-percentile contrast stretch, in place. The raw frame has very
 * low contrast (std ~6); the offline match study (STEP_B_RESULTS.md) showed a
 * global stretch is what exposes the ridges cleanly for NBIS. Cheap, data-only. */
static void
rts5812_normalize_stretch (guint8 *img, gsize n)
{
  guint32 hist[256] = { 0 };
  for (gsize i = 0; i < n; i++)
    hist[img[i]]++;

  gsize lo_target = (n * 2) / 100;
  gsize hi_target = (n * 98) / 100;
  int lo = 0, hi = 255;
  gsize cum = 0;
  for (int v = 0; v < 256; v++) { cum += hist[v]; if (cum >= lo_target) { lo = v; break; } }
  cum = 0;
  for (int v = 0; v < 256; v++) { cum += hist[v]; if (cum >= hi_target) { hi = v; break; } }
  if (hi <= lo)
    return;                       /* flat image: leave untouched */

  int span = hi - lo;
  for (gsize i = 0; i < n; i++)
    {
      int p = ((int) img[i] - lo) * 255 / span;
      img[i] = (guint8) (p < 0 ? 0 : (p > 255 ? 255 : p));
    }
}

/* ------------------------------------------------------------------ */
/* Frame quality and print data                                        */
/* ------------------------------------------------------------------ */

/* Fraction of 8x8 blocks with ridge contrast (block stddev of the high-passed
 * frame > 3). On dataset2 full presses score >= 0.6 and edge-only presses
 * 0.28-0.47, so it cleanly flags a press that mostly missed the sensor. */
static double
rts5812_ridge_coverage (const guint8 *img)
{
  const int W = RTS5812_IMG_W, H = RTS5812_IMG_H, B = 8, R = 4;
  int good = 0, total = 0;
  g_autofree float *hp = g_new (float, RTS5812_IMG_SIZE);

  for (int y = 0; y < H; y++)
    for (int x = 0; x < W; x++)
      {
        int sum = 0, n = 0;
        for (int dy = -R; dy <= R; dy++)
          for (int dx = -R; dx <= R; dx++)
            {
              int yy = CLAMP (y + dy, 0, H - 1), xx = CLAMP (x + dx, 0, W - 1);
              sum += img[yy * W + xx];
              n++;
            }
        hp[y * W + x] = img[y * W + x] - (float) sum / n;
      }
  for (int by = 0; by + B <= H; by += B)
    for (int bx = 0; bx + B <= W; bx += B)
      {
        double s = 0, s2 = 0;
        for (int y = by; y < by + B; y++)
          for (int x = bx; x < bx + B; x++)
            {
              s += hp[y * W + x];
              s2 += hp[y * W + x] * hp[y * W + x];
            }
        s /= B * B;
        good += (s2 / (B * B) - s * s) > RTS5812_BLOCK_VAR_MIN;
        total++;
      }
  return (double) good / total;
}

/* Print data: (format, width, height, [frame, ...]) with raw decoded frames, so
 * the matcher can change without invalidating stored enrollments. */
static GVariant *
rts5812_print_data_new (GPtrArray *frames)
{
  GVariantBuilder b;

  g_variant_builder_init (&b, G_VARIANT_TYPE ("aay"));
  for (guint i = 0; i < frames->len; i++)
    {
      GBytes *f = g_ptr_array_index (frames, i);
      g_variant_builder_add_value (&b, g_variant_new_from_bytes (G_VARIANT_TYPE_BYTESTRING,
                                                                 f, TRUE));
    }
  return g_variant_new ("(qqqaay)", RTS5812_PRINT_FORMAT, RTS5812_IMG_W,
                        RTS5812_IMG_H, &b);
}

static FpPrint *
rts5812_print_new (FpDevice *dev, GPtrArray *frames)
{
  FpPrint *print = fp_print_new (dev);

  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", rts5812_print_data_new (frames), NULL);
  return print;
}

/* Features of an enrolled frame, extracted once and kept for the device's
 * lifetime: fprintd keeps the FpDevice across claims, and re-extracting all
 * stored frames (~40 ms each) dominated the time of every non-matching try. */
static const Rts5812Features *
rts5812_cached_features (FpiDeviceRts5812 *self, const guint8 *px)
{
  g_autoptr(GBytes) key = g_bytes_new (px, RTS5812_IMG_SIZE);
  Rts5812Features *f = g_hash_table_lookup (self->feature_cache, key);

  if (f)
    return f;
  if (g_hash_table_size (self->feature_cache) >= RTS5812_FEATURE_CACHE_MAX)
    g_hash_table_remove_all (self->feature_cache);
  f = rts5812_features_extract (px, RTS5812_IMG_W, RTS5812_IMG_H);
  g_hash_table_insert (self->feature_cache, g_steal_pointer (&key), f);
  return f;
}

/* Best match score of `probe` against the frames stored in `print`; stops at
 * the first frame that clears the threshold. -1 if the print is unusable. */
static int
rts5812_print_score (FpiDeviceRts5812 *self, FpPrint *print,
                     const Rts5812Features *probe)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) frames = NULL;
  guint16 format, w, h;
  int best = 0;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("(qqqaay)")))
    return -1;
  g_variant_get (data, "(qqq@aay)", &format, &w, &h, &frames);
  if (format != RTS5812_PRINT_FORMAT || w != RTS5812_IMG_W || h != RTS5812_IMG_H)
    return -1;

  for (gsize i = 0; i < g_variant_n_children (frames) && best < RTS5812_MATCH_THRESHOLD; i++)
    {
      g_autoptr(GVariant) fv = g_variant_get_child_value (frames, i);
      gsize len;
      const guint8 *px = g_variant_get_fixed_array (fv, &len, 1);

      if (len != RTS5812_IMG_SIZE)
        continue;
      best = MAX (best, rts5812_features_match (probe,
                                                rts5812_cached_features (self, px)));
    }
  return best;
}

static FpImage *
rts5812_frame_to_image (const guint8 *frame)
{
  FpImage *img = fp_image_new (RTS5812_IMG_W, RTS5812_IMG_H);

  memcpy (img->data, frame, RTS5812_IMG_SIZE);
  rts5812_normalize_stretch (img->data, RTS5812_IMG_SIZE);
  return img;
}

/* ------------------------------------------------------------------ */
/* Per-action handling of one captured frame                           */
/* ------------------------------------------------------------------ */

/* Report a failed press to the current action as a retry. */
static void
rts5812_report_retry (FpDevice *dev, FpDeviceRetry retry)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);

  switch (fpi_device_get_current_action (dev))
    {
    case FPI_DEVICE_ACTION_ENROLL:
      fpi_device_enroll_progress (dev, self->enroll_frames->len, NULL,
                                  fpi_device_retry_new (retry));
      break;

    case FPI_DEVICE_ACTION_VERIFY:
      fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, fpi_device_retry_new (retry));
      break;

    case FPI_DEVICE_ACTION_IDENTIFY:
      fpi_device_identify_report (dev, NULL, NULL, fpi_device_retry_new (retry));
      break;

    case FPI_DEVICE_ACTION_CAPTURE:
      g_clear_error (&self->capture_error);
      self->capture_error = fpi_device_retry_new (retry);
      break;

    case FPI_DEVICE_ACTION_NONE:
    case FPI_DEVICE_ACTION_PROBE:
    case FPI_DEVICE_ACTION_OPEN:
    case FPI_DEVICE_ACTION_CLOSE:
    case FPI_DEVICE_ACTION_LIST:
    case FPI_DEVICE_ACTION_DELETE:
    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
    default:
      break;
    }
}

/* self->frame holds a freshly decoded frame: act on it for the current action.
 * Results are reported here, before the finger lifts; the action completes in
 * rts5812_capture_done() once the sensor is idle again. */
static void
rts5812_process_frame (FpDevice *dev)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);
  double coverage = rts5812_ridge_coverage (self->frame);
  g_autoptr(Rts5812Features) probe = NULL;
  g_autoptr(GPtrArray) one = NULL;

  fp_dbg ("rts5812: frame ridge coverage %.2f", coverage);

  if (action == FPI_DEVICE_ACTION_CAPTURE)
    {
      g_clear_object (&self->capture_image);
      self->capture_image = rts5812_frame_to_image (self->frame);
      return;
    }

  if (coverage < (action == FPI_DEVICE_ACTION_ENROLL ?
                  RTS5812_ENROLL_COVERAGE_MIN : RTS5812_MATCH_COVERAGE_MIN))
    {
      rts5812_report_retry (dev, FP_DEVICE_RETRY_CENTER_FINGER);
      return;
    }

  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      g_ptr_array_add (self->enroll_frames,
                       g_bytes_new (self->frame, RTS5812_IMG_SIZE));
      fpi_device_enroll_progress (dev, self->enroll_frames->len, NULL, NULL);
      return;
    }

  /* verify / identify. The scanned print (just this frame) is reported only on
   * a non-match: on a match libfprint checks fp_print_equal(scan, enrolled),
   * which for raw prints is a byte compare that a one-frame scan never passes. */
  one = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  g_ptr_array_add (one, g_bytes_new (self->frame, RTS5812_IMG_SIZE));
  probe = rts5812_features_extract (self->frame, RTS5812_IMG_W, RTS5812_IMG_H);

  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *enrolled;
      int score;

      fpi_device_get_verify_data (dev, &enrolled);
      score = rts5812_print_score (self, enrolled, probe);
      fp_dbg ("rts5812: verify score %d (threshold %d)", score, RTS5812_MATCH_THRESHOLD);
      if (score >= RTS5812_MATCH_THRESHOLD)
        fpi_device_verify_report (dev, FPI_MATCH_SUCCESS, NULL, NULL);
      else
        fpi_device_verify_report (dev, FPI_MATCH_FAIL, rts5812_print_new (dev, one), NULL);
    }
  else if (action == FPI_DEVICE_ACTION_IDENTIFY)
    {
      GPtrArray *gallery;
      FpPrint *match = NULL;

      fpi_device_get_identify_data (dev, &gallery);
      for (guint i = 0; i < gallery->len && !match; i++)
        {
          int score = rts5812_print_score (self, g_ptr_array_index (gallery, i), probe);
          fp_dbg ("rts5812: identify score[%u] %d", i, score);
          if (score >= RTS5812_MATCH_THRESHOLD)
            match = g_ptr_array_index (gallery, i);
        }
      fpi_device_identify_report (dev, match,
                                  match ? NULL : rts5812_print_new (dev, one), NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Asynchronous command (capture path)                                 */
/* ------------------------------------------------------------------ */

/* rts5812_cmd() is synchronous, and gusb implements a "sync" transfer by
 * running a nested main loop on the main context. Inside an SSM handler that
 * nested loop can dispatch the host's own callbacks -- fprintd's
 * client-vanished handler then iterates the main loop waiting for this very
 * action to finish, which it never can: a deadlock that leaves the device
 * claimed forever (seen after a lock-screen match). So everything that runs
 * while an action is in progress uses this sub-SSM instead, which returns to
 * the main loop between the header, data and status phases. Only dev_open
 * still uses the synchronous path. */

enum cmd_states {
  CMD_HEADER,
  CMD_DATA,
  CMD_STATUS,
  CMD_NUM_STATES,
};

typedef struct
{
  guint8   op, reg;
  guint16  len;
  guint8  *data_out;   /* owned copy for writes, NULL for reads      */
  guint8  *data_in;    /* destination for reads (not owned)           */
} CmdData;

static void
cmd_data_free (gpointer p)
{
  CmdData *c = p;

  g_free (c->data_out);
  g_free (c);
}

static void
rts5812_cmd_data_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer user_data,
                     GError *error)
{
  CmdData *c = fpi_ssm_get_data (t->ssm);

  if (error)
    {
      fpi_ssm_mark_failed (t->ssm, error);
      return;
    }
  if (c->data_in)
    memcpy (c->data_in, t->buffer, MIN ((gsize) t->actual_length, c->len));
  fpi_ssm_next_state (t->ssm);
}

static void
rts5812_cmd_status_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer user_data,
                       GError *error)
{
  CmdData *c = fpi_ssm_get_data (t->ssm);

  if (error)
    {
      fpi_ssm_mark_failed (t->ssm, error);
      return;
    }
  if (t->buffer[0] != 0x00)
    {
      fpi_ssm_mark_failed (t->ssm,
                           g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                                        "rts5812 command 0x%02x (reg 0x%02x) status error %d",
                                        c->op, c->reg, t->buffer[0]));
      return;
    }
  fpi_ssm_next_state (t->ssm);
}

static void
rts5812_cmd_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);
  CmdData *c = fpi_ssm_get_data (ssm);
  FpiUsbTransfer *t;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CMD_HEADER:
      {
        guint8 header[RTS5812_HDR_LEN] = {
          RTS5812_HDR_MAGIC, c->op, 0x00, 0x00, c->reg, 0x00,
          (guint8) (c->len & 0xff), (guint8) (c->len >> 8)
        };
        t = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_bulk_full (t, self->ep_out,
                                         g_memdup2 (header, sizeof header),
                                         sizeof header, g_free);
        t->ssm = ssm;
        fpi_usb_transfer_submit (t, RTS5812_USB_TIMEOUT_MS, NULL,
                                 fpi_ssm_usb_transfer_cb, NULL);
        break;
      }

    case CMD_DATA:
      if (c->len == 0)
        {
          fpi_ssm_next_state (ssm);
          break;
        }
      t = fpi_usb_transfer_new (dev);
      if (c->data_out)
        fpi_usb_transfer_fill_bulk_full (t, self->ep_out,
                                         g_memdup2 (c->data_out, c->len),
                                         c->len, g_free);
      else
        fpi_usb_transfer_fill_bulk (t, self->ep_in, c->len);
      t->ssm = ssm;
      fpi_usb_transfer_submit (t, RTS5812_USB_TIMEOUT_MS, NULL,
                               rts5812_cmd_data_cb, NULL);
      break;

    case CMD_STATUS:
      t = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk (t, self->ep_in, RTS5812_STATUS_LEN);
      t->ssm = ssm;
      fpi_usb_transfer_submit (t, RTS5812_USB_TIMEOUT_MS, NULL,
                               rts5812_cmd_status_cb, NULL);
      break;
    }
}

/* Run one command as a child of `parent`; the parent advances to its next
 * state when the command succeeds and fails with its error otherwise. Pass
 * data_out for writes, data_in (len bytes) for reads. */
static void
rts5812_cmd_async (FpiSsm *parent, guint8 op, guint8 reg,
                   const guint8 *data_out, guint8 *data_in, guint16 len)
{
  CmdData *c = g_new0 (CmdData, 1);
  FpiSsm *child = fpi_ssm_new (fpi_ssm_get_device (parent), rts5812_cmd_ssm,
                               CMD_NUM_STATES);

  c->op = op;
  c->reg = reg;
  c->len = len;
  c->data_out = data_out ? g_memdup2 (data_out, len) : NULL;
  c->data_in = data_in;
  fpi_ssm_set_data (child, c, cmd_data_free);
  fpi_ssm_silence_debug (child);
  fpi_ssm_start_subsm (parent, child);
}

/* ------------------------------------------------------------------ */
/* Capture state machine                                               */
/* ------------------------------------------------------------------ */

/* Each step that talks to the sensor is split in two: issue the command
 * (async), then act on its result in the following state. */
enum capture_states {
  CAP_WAIT_IDLE,        /* status: no finger/frame latched from before  */
  CAP_WAIT_IDLE_CHECK,
  CAP_DRAIN,            /* still latched after ~1 s: read + discard it  */
  CAP_SET_MODE,         /* setSensorMode(1) to arm                     */
  CAP_SET_MODE_DONE,
  CAP_POLL,             /* getImageStatus until frame ready (finger on) */
  CAP_POLL_CHECK,
  CAP_READ,             /* getImageData                                */
  CAP_READ_DONE,        /* verify/decrypt + process                    */
  CAP_LIFT,             /* poll until the finger lifts                 */
  CAP_LIFT_CHECK,
  CAP_NUM_STATES,
};

static void
rts5812_capture_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);
  g_autoptr(GError) error = NULL;

  /* Cancellation is checked on every step; polling steps run every 128 ms,
   * so a cancel takes effect within one poll interval. */
  if (g_cancellable_set_error_if_cancelled (fpi_device_get_cancellable (dev), &error))
    {
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAP_WAIT_IDLE:
    case CAP_POLL:
    case CAP_LIFT:
      self->status = 0;
      rts5812_cmd_async (ssm, RTS5812_OP_IMAGE_STATUS, 0x00, NULL, &self->status, 1);
      break;

    case CAP_WAIT_IDLE_CHECK:
      /* A previous action may have been cancelled with the finger still
       * down; arming over a latched frame corrupts the next capture. But the
       * status can also stay set with no finger at all (seen right after
       * bring-up), so only wait ~1 s -- and not at all on the first capture
       * after open, where that quirk is the usual cause -- then drain the
       * latched frame and arm anyway: worst case one press is retried. */
      if (self->status != 1)
        fpi_ssm_jump_to_state (ssm, CAP_SET_MODE);
      else if (!self->fresh_open && ++self->poll_count < RTS5812_IDLE_MAX_POLLS)
        fpi_ssm_jump_to_state_delayed (ssm, CAP_WAIT_IDLE, RTS5812_POLL_INTERVAL_MS);
      else
        fpi_ssm_next_state (ssm);                     /* -> CAP_DRAIN */
      break;

    case CAP_DRAIN:
      fp_dbg ("rts5812: image status stuck at 1, draining latched frame");
      rts5812_cmd_async (ssm, RTS5812_OP_GET_IMAGE, 0x00, NULL, self->xfer,
                         RTS5812_XFER_LEN);           /* -> CAP_SET_MODE */
      break;

    case CAP_SET_MODE:
      {
        guint8 mode = RTS5812_SENSOR_MODE_CAPTURE;
        rts5812_cmd_async (ssm, RTS5812_OP_SET_MODE, 0x00, &mode, NULL, 1);
        break;
      }

    case CAP_SET_MODE_DONE:
      self->fresh_open = FALSE;
      self->poll_count = 0;
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_NONE);
      fpi_ssm_next_state (ssm);
      break;

    case CAP_POLL_CHECK:
      if (self->status == 1)
        {
          fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT,
                                                   FP_FINGER_STATUS_NEEDED);
          fpi_ssm_next_state (ssm);
        }
      else
        {
          /* Poll every 128 ms, re-arming every 16 polls, matching the Windows
           * capture thread. The delay is essential: without it the re-arm
           * fires ~128x too often and the sensor never detects a finger. */
          if (++self->poll_count % RTS5812_REARM_EVERY == 0)
            fpi_ssm_jump_to_state_delayed (ssm, CAP_SET_MODE,
                                           RTS5812_POLL_INTERVAL_MS);
          else
            fpi_ssm_jump_to_state_delayed (ssm, CAP_POLL,
                                           RTS5812_POLL_INTERVAL_MS);
        }
      break;

    case CAP_READ:
      rts5812_cmd_async (ssm, RTS5812_OP_GET_IMAGE, 0x00, NULL, self->xfer,
                         RTS5812_XFER_LEN);
      break;

    case CAP_READ_DONE:
      {
        int rc;

        /* The frame carries its own SID; decode derives keys from it (and K). */
        memcpy (self->sid, self->xfer + RTS5812_SID_OFF, RTS5812_SID_LEN);

        rc = rts5812_decode_frame (self->xfer, RTS5812_XFER_LEN, self->master_key,
                                   self->frame);
        if (rc != 0)
          {
            /* A bad frame (CMAC mismatch / malformed) is a failed scan, not a
             * fatal session error: report a retry and wait for the lift. */
            fp_warn ("rts5812: frame decode failed (rc=%d: %s)", rc,
                     rc == -2 ? "CMAC mismatch" : "bad frame");
            rts5812_report_retry (dev, FP_DEVICE_RETRY_GENERAL);
          }
        else
          {
            rts5812_process_frame (dev);
          }
        self->poll_count = 0;
        fpi_ssm_next_state (ssm);                     /* -> CAP_LIFT */
        break;
      }

    case CAP_LIFT_CHECK:
      /* Don't finish until the finger is really off and the sensor's
       * ready-state has cleared (getImageStatus == 0), then settle -- the
       * probe's wait_finger_lift. Re-arming over a latched frame makes the
       * following capture decode fail its CMAC. */
      if (self->status != 1)
        {
          fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE,
                                                   FP_FINGER_STATUS_PRESENT);
          fpi_ssm_mark_completed_delayed (ssm, RTS5812_LIFT_SETTLE_MS);
        }
      else
        {
          fpi_ssm_jump_to_state_delayed (ssm, CAP_LIFT, RTS5812_POLL_INTERVAL_MS);
        }
      break;
    }
}

static void rts5812_capture_done (FpiSsm *ssm, FpDevice *dev, GError *error);

static void
rts5812_start_capture (FpDevice *dev)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);

  self->poll_count = 0;
  self->ssm = fpi_ssm_new (dev, rts5812_capture_ssm, CAP_NUM_STATES);
  fpi_ssm_start (self->ssm, rts5812_capture_done);
}

/* One press is fully handled (finger lifted): finish the action, or for
 * enroll start the next press until every stage is filled. */
static void
rts5812_capture_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  self->ssm = NULL;
  fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);

  switch (action)
    {
    case FPI_DEVICE_ACTION_ENROLL:
      if (!error && (gint) self->enroll_frames->len < fp_device_get_nr_enroll_stages (dev))
        {
          rts5812_start_capture (dev);
          return;
        }
      if (error)
        {
          fpi_device_enroll_complete (dev, NULL, error);
        }
      else
        {
          FpPrint *print;

          fpi_device_get_enroll_data (dev, &print);
          fpi_print_set_type (print, FPI_PRINT_RAW);
          g_object_set (print, "fpi-data",
                        rts5812_print_data_new (self->enroll_frames), NULL);
          fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
        }
      g_ptr_array_set_size (self->enroll_frames, 0);
      break;

    case FPI_DEVICE_ACTION_VERIFY:
      fpi_device_verify_complete (dev, error);
      break;

    case FPI_DEVICE_ACTION_IDENTIFY:
      fpi_device_identify_complete (dev, error);
      break;

    case FPI_DEVICE_ACTION_CAPTURE:
      if (!error && self->capture_error)
        error = g_steal_pointer (&self->capture_error);
      g_clear_error (&self->capture_error);
      if (error)
        {
          g_clear_object (&self->capture_image);
          fpi_device_capture_complete (dev, NULL, error);
        }
      else
        {
          fpi_device_capture_complete (dev, g_steal_pointer (&self->capture_image), NULL);
        }
      break;

    case FPI_DEVICE_ACTION_NONE:
    case FPI_DEVICE_ACTION_PROBE:
    case FPI_DEVICE_ACTION_OPEN:
    case FPI_DEVICE_ACTION_CLOSE:
    case FPI_DEVICE_ACTION_LIST:
    case FPI_DEVICE_ACTION_DELETE:
    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
    default:
      g_clear_error (&error);
      break;
    }
}

/* ------------------------------------------------------------------ */
/* FpDevice vfuncs                                                     */
/* ------------------------------------------------------------------ */

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);

  g_ptr_array_set_size (self->enroll_frames, 0);
  rts5812_start_capture (dev);
}

static void
dev_capture (FpDevice *dev)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);

  g_clear_error (&self->capture_error);
  g_clear_object (&self->capture_image);
  rts5812_start_capture (dev);
}

static void
dev_open (FpDevice *dev)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (dev);
  g_autoptr(GError) error = NULL;
  guint8 who = 0;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (dev),
                                     RTS5812_INTERFACE, 0, &error))
    { fpi_device_open_complete (dev, g_steal_pointer (&error)); return; }

  self->ep_in = RTS5812_EP_BULK_IN;
  self->ep_out = RTS5812_EP_BULK_OUT;
  self->session_open = FALSE;

  /* Smoke test: whoami must be 0xAD, then cache K + the start material. */
  if (!rts5812_read_reg8 (self, RTS5812_REG_WHOAMI, &who, &error) ||
      who != RTS5812_WHOAMI_VAL)
    {
      if (!error)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                          "unexpected whoami 0x%02x", who);
      fpi_device_open_complete (dev, g_steal_pointer (&error));
      return;
    }
  if (!rts5812_load_keyblob (self, &error))
    { fpi_device_open_complete (dev, g_steal_pointer (&error)); return; }

  self->fresh_open = TRUE;

  /* Cold bring-up + authenticated session, exactly the proven
   * --reset --warm-dmp --open-session chain. There is no warm shortcut: by the
   * next open the responder has always disarmed itself (0x0E=0x42, seen on
   * every fprintd claim), so each open needs the full bring-up. */
  if (!rts5812_warm_dmp (self, &error) ||
      !rts5812_open_session_verified (self, &error))
    { fpi_device_open_complete (dev, g_steal_pointer (&error)); return; }

  fpi_device_open_complete (dev, NULL);
}

static void
dev_close (FpDevice *dev)
{
  GError *error = NULL;

  g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                  RTS5812_INTERFACE, 0, &error);
  fpi_device_close_complete (dev, error);
}

/* ------------------------------------------------------------------ */
/* GObject / driver registration                                       */
/* ------------------------------------------------------------------ */

static const FpIdEntry id_table[] = {
  { .vid = RTS5812_VID, .pid = RTS5812_PID },
  { .vid = 0, .pid = 0 },
};

static void
fpi_device_rts5812_init (FpiDeviceRts5812 *self)
{
  self->enroll_frames = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  self->xfer = g_malloc0 (RTS5812_XFER_LEN);
  self->feature_cache = g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
                                               (GDestroyNotify) g_bytes_unref,
                                               (GDestroyNotify) rts5812_features_free);
}

static void
fpi_device_rts5812_finalize (GObject *object)
{
  FpiDeviceRts5812 *self = FPI_DEVICE_RTS5812 (object);

  g_clear_pointer (&self->enroll_frames, g_ptr_array_unref);
  g_clear_pointer (&self->xfer, g_free);
  g_clear_pointer (&self->feature_cache, g_hash_table_unref);
  g_clear_error (&self->capture_error);
  g_clear_object (&self->capture_image);
  G_OBJECT_CLASS (fpi_device_rts5812_parent_class)->finalize (object);
}

static void
fpi_device_rts5812_class_init (FpiDeviceRts5812Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  G_OBJECT_CLASS (klass)->finalize = fpi_device_rts5812_finalize;

  dev_class->id = "rts5812";
  dev_class->full_name = "Realtek RTS5812 / TDK TCFS2000 fingerprint";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  /* A small partial sensor: matching only works when a probe overlaps an
   * enrolled frame, so enroll many presses to cover the finger (offline,
   * false rejects fell from 44% at 3 presses to 18% at 7). */
  dev_class->nr_enroll_stages = RTS5812_ENROLL_STAGES;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = rts5812_start_capture;
  dev_class->identify = rts5812_start_capture;
  dev_class->capture = dev_capture;

  fpi_device_class_auto_initialize_features (dev_class);
}
