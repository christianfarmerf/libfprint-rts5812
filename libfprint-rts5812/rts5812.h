/* rts5812.h — Realtek RTS5812 + TDK TCFS2000 fingerprint bridge, protocol
 * constants for the libfprint driver. See ../PROTOCOL.md. */
#ifndef RTS5812_H
#define RTS5812_H

#include <glib.h>

#define RTS5812_VID 0x0bda
#define RTS5812_PID 0x5812

#define RTS5812_INTERFACE 0
#define RTS5812_EP_BULK_OUT 0x01
#define RTS5812_EP_BULK_IN  0x82
/* 0x83 / 0x84 are interrupt INs (sensor events); polling getImageStatus is
 * enough for a first driver, so they are left unused here. */

#define RTS5812_USB_TIMEOUT_MS 4000

/* Command framing: 8-byte OUT header  F0 <op> 00 00 <reg> 00 <len_lo> <len_hi>,
 * then the data phase (IN for reads, OUT for writes), then a 5-byte IN status
 * whose byte 0 == 0 means success. */
#define RTS5812_HDR_MAGIC 0xF0
#define RTS5812_HDR_LEN   8
#define RTS5812_STATUS_LEN 5

#define RTS5812_OP_READ_REG      0xE1  /* readReg(reg, len)        IN  len    */
#define RTS5812_OP_WRITE_REG     0x61  /* writeReg(reg, buf, len)  OUT len    */
#define RTS5812_OP_GET_IMAGE     0x62  /* getImageData(len)        IN  len    */
#define RTS5812_OP_IMAGE_STATUS  0x63  /* getImageStatus()         IN  1      */
#define RTS5812_OP_SET_MODE      0xE4  /* setSensorMode(mode)      OUT 1      */
#define RTS5812_OP_STORE_KEY     0x68  /* storeSecSessionKey       OUT len    */
#define RTS5812_OP_RETRIEVE_KEY  0xE8  /* retrieveSecSessionKey    IN  len    */

/* Sensor whoami: read_reg8(0x00) must be 0xAD (serial_read of reg|0x80). */
#define RTS5812_REG_WHOAMI 0x00
#define RTS5812_WHOAMI_VAL 0xAD

#define RTS5812_SENSOR_MODE_CAPTURE 1

/* Capture poll cadence. The Windows capture thread (and the proven Python probe)
 * poll getImageStatus every 128 ms and re-arm setSensorMode only every 16 polls
 * (~2 s). Polling with no delay re-arms ~128x too fast and the sensor never
 * settles to detect a finger, so this interval is load-bearing, not cosmetic. */
#define RTS5812_POLL_INTERVAL_MS 128
#define RTS5812_REARM_EVERY      16
/* Before arming, wait at most this many polls (~1 s) for a latched "frame
 * ready" status to clear before draining it; it can stick with no finger. */
#define RTS5812_IDLE_MAX_POLLS   8
/* After reading a frame, wait for the finger to actually lift (getImageStatus
 * back to 0) before re-arming, then settle, exactly as the probe does. Re-arming
 * while the previous frame's ready-state is still latched corrupts the next
 * capture (its frame fails CMAC), so this lift-wait is load-bearing too. */
#define RTS5812_LIFT_SETTLE_MS   150

/* ---- host-side matching (see rts5812_match.h) ------------------------ */
/* Presses captured per enrollment: the sensor sees ~7x3 mm per press, so a
 * finger needs many presses to cover; offline FRR fell steadily with count. */
#define RTS5812_ENROLL_STAGES       12
/* Ridge coverage gate (fraction of 8x8 blocks with ridge contrast): enroll
 * frames must be mostly finger; matching tolerates partial presses. */
#define RTS5812_BLOCK_VAR_MIN       9.0    /* block stddev > 3 */
#define RTS5812_ENROLL_COVERAGE_MIN 0.55
#define RTS5812_MATCH_COVERAGE_MIN  0.20
/* Enrolled-frame features kept in memory (~80 KB each); cleared when full. */
#define RTS5812_FEATURE_CACHE_MAX   64
/* Version of the print data layout: (format, w, h, [raw frames]). */
#define RTS5812_PRINT_FORMAT        1

/* getImageData transfer size; first RTS5812_FRAME_LEN bytes are the frame. */
#define RTS5812_XFER_LEN 0x4200

/* ---- DMP (digital-motion-processor) memory + status registers ----------- */
/* write_dmp_mem: set the 4-byte LE pointer in reg 0x08, then stream data into
 * reg 0x0C (pointer auto-advances); read_dmp_mem streams out of reg 0x8C.    */
#define RTS5812_REG_DMP_ADDR   0x08
#define RTS5812_REG_DMP_WRITE  0x0C
#define RTS5812_REG_DMP_READ   0x8C
#define RTS5812_REG_DMP_STATUS 0x0E   /* wait_dmp_idle polls this; idle iff (v&6)==2 */

/* The bridge's writeReg handler rejects payloads near its max transfer, so DMP
 * streams are chunked to one bulk packet minus a byte (max_xfer-1 = 511).     */
#define RTS5812_DMP_CHUNK      0x1FF
#define RTS5812_DMP_FW_ADDR    0x10000 /* DMP address the firmware uploads to  */

/* DMP data addresses poked during bring-up (see rts5812_probe.py). */
#define RTS5812_DMP_GAINCOMP_ADDR 0x16AAF  /* bypass_gain_comp_enable: =3 on / 0 off */
#define RTS5812_DMP_CUSTGEN_ADDR  0x16E18  /* applyCustomGenerator: LE32 0x0000005A  */
#define RTS5812_DMP_FWVER_ADDR    0x16964  /* 12-byte firmware version string        */

/* ---- security-session responder (inv_fp_start / inv_fp_open_session) ----- */
/* reg 0x0D: write 4 to arm the responder (inv_fp_start), 8 to open a session. */
#define RTS5812_REG_SESSION_TRIGGER 0x0D
#define RTS5812_SESSION_START_VAL   0x04
#define RTS5812_SESSION_OPEN_VAL    0x08
#define RTS5812_REG_SESSION_RESP    0x87   /* read the 16-byte CMAC reply from here */
#define RTS5812_REG_DMP_READY       0x39   /* open-session ready-poll: wait (v&4)==0 */

/* 0x0E status bits. The responder is "serviceable" when bit 0x08 is set and
 * bit 0x40 is clear; the modes alone leave 0x22 (bit 0x20), inv_fp_start flips
 * 0x08 -> 0x0a. */
#define RTS5812_DMP_BIT_BUSY   0x01
#define RTS5812_DMP_BIT_IDLE   0x02
#define RTS5812_DMP_BIT_MODE   0x20
#define RTS5812_DMP_BIT_ARMED  0x08
#define RTS5812_DMP_BIT_BLOCK  0x40

/* DMP addresses + lengths for the session handshake. */
#define RTS5812_SID_DMP_ADDR    0x3D0   /* inv_fp_open_session writes the SID here   */
#define RTS5812_START_DMP_ADDR  0x00    /* inv_fp_start writes start material here    */
#define RTS5812_START_BLOB_OFF  0x3C    /* blob[0x3C:0x3B4] = per-device start material */
#define RTS5812_START_BLOB_LEN  0x378

/* setupDevice mode sequence; applyCustomGenerator runs just before mode 5. */
#define RTS5812_MODE_1  1
#define RTS5812_MODE_14 14
#define RTS5812_MODE_5  5

#endif /* RTS5812_H */
