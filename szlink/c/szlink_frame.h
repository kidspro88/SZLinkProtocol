/**
 * @file szlink_frame.h
 * @brief SZ-Link frame layer: LCID + SEC framing on top of MAVLink 2 messages,
 *        with optional authentication/encryption and video FEC.
 *
 * Wire format (all multi-byte fields little-endian):
 *
 *   STX | LEN | LCID | SEQ | SYSID | COMPID | MSGID (3) | PAYLOAD (LEN) | SEC | [TAG] | CRC (2)
 *   0xFD  1B    1B     1B    1B      1B       3B          0..255 B        1B    8/16B   2B
 *
 * - LCID: logical channel (SZ_LCID: 0 = RC, 1 = Telemetry, 2 = Video).
 * - SEC:  SZ_SEC_FLAGS: bit 0 encrypted, bits 1-2 key epoch (mod 4),
 *         bit 3 FEC, bit 4 signed (authenticated, not encrypted).
 * - TAG:  present when SEC has the encrypted or signed bit: 8 bytes on LCID
 *         RC, 16 bytes otherwise. LEN does not count it. See szlink_sec.h.
 * - CRC:  CRC-16/MCRF4XX (the MAVLink X.25 CRC) over LEN..TAG followed by
 *         the message's CRC_EXTRA, as MAVLink 2 does.
 * - PAYLOAD uses MAVLink 2 payload encoding, including trailing-zero trimming.
 *   When encrypted, SEQ carries the low byte of the frame counter.
 * - FEC:  a frame with the SEC FEC bit is sent inside a Reed-Solomon envelope
 *         (szlink_ecc.h), which starts with 0xEC. Only video frames use it.
 *
 * Include after the generated dialect header, e.g.:
 *
 *   #include "spacezet/szlink.h"
 *   #include "szlink_frame.h"
 *
 * and in exactly one translation unit define SZLINK_SEC_IMPLEMENTATION and
 * SZLINK_ECC_IMPLEMENTATION first, and link Monocypher. No dynamic
 * allocation; one parser instance per link.
 */
#ifndef SZLINK_FRAME_H
#define SZLINK_FRAME_H

#include <stdint.h>
#include <string.h>

#ifndef SZLINK_VERSION
#error "Include the generated dialect header (e.g. spacezet/szlink.h) before szlink_frame.h"
#endif

#include "szlink_ecc.h"
#include "szlink_sec.h"

#define SZLINK_FRAME_STX         0xFDu
#define SZLINK_FRAME_HEADER_LEN  9u  /* STX LEN LCID SEQ SYSID COMPID MSGID[3] */
#define SZLINK_FRAME_TRAILER_LEN 3u  /* SEC CRC[2] */
#define SZLINK_FRAME_TAG_MAX     SZLINK_SEC_TAG_MAX
#define SZLINK_FRAME_OVERHEAD    (SZLINK_FRAME_HEADER_LEN + SZLINK_FRAME_TRAILER_LEN)
#define SZLINK_FRAME_MAX_LEN     (SZLINK_FRAME_OVERHEAD + 255u + SZLINK_FRAME_TAG_MAX)
#define SZLINK_FRAME_FEC_MAX_NSYM 32u
/* an envelope of a maximum frame needs two RS blocks */
#define SZLINK_FRAME_FEC_MAX_LEN (SZLINK_ECC_HEADER_LEN + SZLINK_FRAME_MAX_LEN + \
                                  2u * SZLINK_FRAME_FEC_MAX_NSYM)

typedef struct {
    uint8_t buf[SZLINK_FRAME_FEC_MAX_LEN];
    uint8_t scratch[SZLINK_FRAME_FEC_MAX_LEN];
    uint8_t inner[SZLINK_FRAME_MAX_LEN];
    uint16_t idx;              /* bytes buffered */
    /* configuration */
    szlink_sec_t *sec;         /* NULL: protected frames are dropped */
    uint32_t now_ms;           /* set by the caller before feeding bytes */
    uint8_t fec_nsym;          /* 0: FEC envelopes are not accepted */
    /* about the last decoded frame */
    uint8_t authenticated;     /* tag verified (and payload decrypted) */
    uint8_t via_fec;           /* arrived in an FEC envelope */
    /* statistics */
    uint32_t rx_ok;            /* frames accepted */
    uint32_t crc_errors;       /* frames dropped for a bad CRC */
    uint32_t unknown_msgid;    /* frames dropped because the msgid is unknown */
    uint32_t len_errors;       /* LEN exceeds the message's max length, or FEC bit mismatch */
    uint32_t auth_errors;      /* protected frames that did not authenticate */
    uint32_t fec_errors;       /* uncorrectable FEC envelopes */
    uint32_t fec_corrected;    /* bytes repaired by FEC */
} szlink_frame_parser_t;

static inline uint16_t szlink_frame_crc(const uint8_t *frame, uint16_t covered, uint8_t crc_extra)
{
    uint16_t crc;
    /* LEN .. SEC/TAG: `covered` bytes after STX */
    crc_init(&crc);
    crc_accumulate_buffer(&crc, (const char *)frame + 1, covered);
    crc_accumulate(crc_extra, &crc);
    return crc;
}

/* write header, return the message's CRC_EXTRA (or -1) */
static inline int szlink_frame_header_(uint8_t *buf, const szlink_message_t *msg, uint8_t lcid)
{
    const szlink_msg_entry_t *e = szlink_get_msg_entry(msg->msgid);
    if (e == NULL || msg->sysid > 0xFFu) {
        return -1;
    }
    buf[0] = SZLINK_FRAME_STX;
    buf[1] = msg->len;
    buf[2] = lcid;
    buf[3] = msg->seq;
    buf[4] = (uint8_t)msg->sysid;
    buf[5] = msg->compid;
    buf[6] = (uint8_t)(msg->msgid & 0xFFu);
    buf[7] = (uint8_t)((msg->msgid >> 8) & 0xFFu);
    buf[8] = (uint8_t)((msg->msgid >> 16) & 0xFFu);
    memcpy(&buf[SZLINK_FRAME_HEADER_LEN], _MAV_PAYLOAD(msg), msg->len);
    return e->crc_extra;
}

static inline uint16_t szlink_frame_finish_(uint8_t *buf, uint8_t len, uint8_t tag_len,
                                            uint8_t crc_extra)
{
    uint16_t covered = (uint16_t)(SZLINK_FRAME_HEADER_LEN - 1u + len + 1u + tag_len);
    uint16_t crc = szlink_frame_crc(buf, covered, crc_extra);
    buf[1u + covered] = (uint8_t)(crc & 0xFFu);
    buf[2u + covered] = (uint8_t)(crc >> 8);
    return (uint16_t)(SZLINK_FRAME_OVERHEAD + len + tag_len);
}

/**
 * Serialize a packed message into an unprotected SZ-Link frame.
 *
 * @param buf  output buffer of at least SZLINK_FRAME_MAX_LEN bytes
 * @param msg  message built by a generated szlink_msg_*_pack/encode helper
 * @param lcid logical channel (SZ_LCID)
 * @param sec  SEC flags; must not have the encrypted or signed bit (use
 *             szlink_frame_serialize_secure for those)
 * @return frame length in bytes, or 0 if the message cannot be sent
 *         (unknown msgid, SYSID that does not fit in one byte, bad flags)
 */
static inline uint16_t szlink_frame_serialize(uint8_t *buf, const szlink_message_t *msg,
                                              uint8_t lcid, uint8_t sec)
{
    int crc_extra;
    if (sec & SZLINK_SEC_PROTECTED) {
        return 0;
    }
    crc_extra = szlink_frame_header_(buf, msg, lcid);
    if (crc_extra < 0) {
        return 0;
    }
    buf[SZLINK_FRAME_HEADER_LEN + msg->len] = sec;
    return szlink_frame_finish_(buf, msg->len, 0, (uint8_t)crc_extra);
}

/**
 * Serialize a message into a signed or encrypted frame.
 *
 * @param mode  SZLINK_SEC_ENCRYPTED or SZLINK_SEC_SIGNED
 * @param flags extra SEC flags (SZLINK_SEC_FEC), authenticated with the frame
 * @return frame length, or 0 (no session, unknown msgid, ...)
 */
static inline uint16_t szlink_frame_serialize_secure(uint8_t *buf, const szlink_message_t *msg,
                                                     uint8_t lcid, uint8_t mode, uint8_t flags,
                                                     szlink_sec_t *sec, uint32_t now_ms)
{
    uint8_t sec_byte = 0;
    int crc_extra, tag_len;
    crc_extra = szlink_frame_header_(buf, msg, lcid);
    if (crc_extra < 0 || sec == NULL) {
        return 0;
    }
    tag_len = szlink_sec_seal(sec, buf, &buf[SZLINK_FRAME_HEADER_LEN], msg->len, mode, flags,
                              now_ms, &sec_byte, &buf[SZLINK_FRAME_HEADER_LEN + msg->len + 1u]);
    if (tag_len < 0) {
        return 0;
    }
    buf[SZLINK_FRAME_HEADER_LEN + msg->len] = sec_byte;
    return szlink_frame_finish_(buf, msg->len, (uint8_t)tag_len, (uint8_t)crc_extra);
}

/**
 * Wrap a frame (serialized with the SZLINK_SEC_FEC flag) in an FEC envelope.
 * @param out of at least SZLINK_FRAME_FEC_MAX_LEN bytes
 * @return envelope length, or 0
 */
static inline uint16_t szlink_frame_fec_encode(uint8_t *out, const uint8_t *frame, uint16_t len,
                                               uint8_t nsym)
{
    int n;
    if (nsym > SZLINK_FRAME_FEC_MAX_NSYM) {
        return 0;
    }
    n = szlink_ecc_encode(frame, len, nsym, out, SZLINK_FRAME_FEC_MAX_LEN);
    return n < 0 ? 0 : (uint16_t)n;
}

static inline void szlink_frame_parser_init(szlink_frame_parser_t *p)
{
    memset(p, 0, sizeof(*p));
}

enum {
    SZLINK_FRAME_NEED_ = 0, /* incomplete: wait for more bytes */
    SZLINK_FRAME_OK_,       /* msg holds the frame */
    SZLINK_FRAME_BAD_,      /* not a frame: resync at the next start byte */
    SZLINK_FRAME_SKIP_      /* a valid frame we cannot use: skip all of it */
};

/* Check a frame at b (avail bytes); *total gets its length when known. */
static inline int szlink_frame_check_(szlink_frame_parser_t *p, uint8_t *b, uint16_t avail,
                                      uint8_t via_fec, szlink_message_t *msg, uint8_t *lcid,
                                      uint8_t *sec, uint16_t *total)
{
    const szlink_msg_entry_t *e;
    uint8_t len, s, tag_len;
    uint32_t msgid;
    uint16_t crc, rx_crc, covered;

    if (avail < 2u) {
        return SZLINK_FRAME_NEED_;
    }
    len = b[1];
    if (avail < SZLINK_FRAME_HEADER_LEN + len + 1u) {
        return SZLINK_FRAME_NEED_;
    }
    s = b[SZLINK_FRAME_HEADER_LEN + len];
    tag_len = (s & SZLINK_SEC_PROTECTED) ? szlink_sec_tag_len(b[2]) : 0u;
    *total = (uint16_t)(SZLINK_FRAME_OVERHEAD + len + tag_len);
    if (avail < *total) {
        return SZLINK_FRAME_NEED_;
    }
    msgid = (uint32_t)b[6] | ((uint32_t)b[7] << 8) | ((uint32_t)b[8] << 16);
    e = szlink_get_msg_entry(msgid);
    if (e == NULL) {
        p->unknown_msgid++;
        return SZLINK_FRAME_BAD_;
    }
    if (len > e->max_msg_len) {
        p->len_errors++;
        return SZLINK_FRAME_BAD_;
    }
    covered = (uint16_t)(*total - 3u);
    crc = szlink_frame_crc(b, covered, e->crc_extra);
    rx_crc = (uint16_t)(b[1u + covered] | (b[2u + covered] << 8));
    if (crc != rx_crc) {
        p->crc_errors++;
        return SZLINK_FRAME_BAD_;
    }
    if (((s & SZLINK_SEC_FEC) != 0) != (via_fec != 0)) {
        /* the FEC bit is authenticated: it must match how the frame came */
        p->len_errors++;
        return SZLINK_FRAME_SKIP_;
    }
    p->authenticated = 0;
    if (tag_len) {
        if (p->sec == NULL ||
            szlink_sec_open(p->sec, b, &b[SZLINK_FRAME_HEADER_LEN], len, s,
                            &b[SZLINK_FRAME_HEADER_LEN + len + 1u], tag_len, p->now_ms) != 0) {
            p->auth_errors++;
            return SZLINK_FRAME_SKIP_;
        }
        p->authenticated = 1u;
    }
    memset(msg, 0, sizeof(*msg));
    msg->magic = SZLINK_STX;
    msg->len = len;
    msg->seq = b[3];
    msg->sysid = b[4];
    msg->compid = b[5];
    msg->msgid = msgid;
    msg->checksum = crc;
    memcpy(_MAV_PAYLOAD_NON_CONST(msg), &b[SZLINK_FRAME_HEADER_LEN], len);
    *lcid = b[2];
    *sec = s;
    p->via_fec = via_fec;
    p->rx_ok++;
    return SZLINK_FRAME_OK_;
}

static inline int szlink_frame_check_envelope_(szlink_frame_parser_t *p, szlink_message_t *msg,
                                               uint8_t *lcid, uint8_t *sec, uint16_t *total)
{
    int n, plen, fixed = 0, r;
    uint16_t inner_total = 0;
    if (p->idx < SZLINK_ECC_HEADER_LEN) {
        return SZLINK_FRAME_NEED_;
    }
    n = szlink_ecc_frame_length(p->buf, p->idx, p->fec_nsym);
    if (n < 0 || n > (int)SZLINK_FRAME_FEC_MAX_LEN) {
        return SZLINK_FRAME_BAD_;
    }
    *total = (uint16_t)n;
    if (p->idx < *total) {
        return SZLINK_FRAME_NEED_;
    }
    memcpy(p->scratch, p->buf, *total); /* decoding corrects in place */
    plen = szlink_ecc_decode(p->scratch, *total, p->fec_nsym, p->inner, sizeof(p->inner), &fixed);
    if (plen < 0) {
        p->fec_errors++;
        return SZLINK_FRAME_BAD_;
    }
    r = szlink_frame_check_(p, p->inner, (uint16_t)plen, 1u, msg, lcid, sec, &inner_total);
    if (r == SZLINK_FRAME_OK_ && inner_total != (uint16_t)plen) {
        p->rx_ok--;
        p->len_errors++;
        return SZLINK_FRAME_BAD_;
    }
    if (r == SZLINK_FRAME_NEED_) {
        return SZLINK_FRAME_BAD_;
    }
    if (r == SZLINK_FRAME_OK_) {
        p->fec_corrected += (uint32_t)fixed;
    }
    return r;
}

/* Drop the first n buffered bytes, then any bytes before the next start byte. */
static inline void szlink_frame_consume_(szlink_frame_parser_t *p, uint16_t n)
{
    uint16_t k = n;
    while (k < p->idx && p->buf[k] != SZLINK_FRAME_STX &&
           !(p->fec_nsym && p->buf[k] == SZLINK_ECC_MAGIC)) {
        k++;
    }
    memmove(p->buf, &p->buf[k], (size_t)(p->idx - k));
    p->idx = (uint16_t)(p->idx - k);
}

/**
 * Feed one received byte. Set p->now_ms (and p->sec / p->fec_nsym) first.
 *
 * @return 1 when a complete, CRC-valid (and, if protected, authenticated and
 *         decrypted) frame has been decoded into msg / lcid / sec; p->authenticated
 *         and p->via_fec describe it. 0 otherwise.
 *
 * After a bad frame the parser rescans the buffered bytes for the next start
 * byte, so a frame that starts inside a corrupted one is not lost. Bytes
 * buffered after a decoded frame are kept; call szlink_frame_parse_next()
 * until it returns 0 to drain frames that are already complete.
 */
static inline int szlink_frame_parse_next(szlink_frame_parser_t *p, szlink_message_t *msg,
                                          uint8_t *lcid, uint8_t *sec)
{
    for (;;) {
        uint16_t total = 0;
        int r;
        if (p->idx == 0u) {
            return 0;
        }
        if (p->buf[0] == SZLINK_FRAME_STX) {
            r = szlink_frame_check_(p, p->buf, p->idx, 0u, msg, lcid, sec, &total);
        } else {
            r = szlink_frame_check_envelope_(p, msg, lcid, sec, &total);
        }
        switch (r) {
        case SZLINK_FRAME_NEED_:
            if (p->idx >= sizeof(p->buf)) {
                szlink_frame_consume_(p, 1u); /* cannot be a frame */
                continue;
            }
            return 0;
        case SZLINK_FRAME_OK_:
            szlink_frame_consume_(p, total);
            return 1;
        case SZLINK_FRAME_SKIP_:
            szlink_frame_consume_(p, total);
            break;
        default:
            szlink_frame_consume_(p, 1u);
            break;
        }
        /* the remaining bytes may already be a complete frame: loop */
    }
}

static inline int szlink_frame_parse_char(szlink_frame_parser_t *p, uint8_t c,
                                          szlink_message_t *msg, uint8_t *lcid, uint8_t *sec)
{
    if (p->idx == 0u && c != SZLINK_FRAME_STX && !(p->fec_nsym && c == SZLINK_ECC_MAGIC)) {
        return 0;
    }
    if (p->idx >= sizeof(p->buf)) {
        szlink_frame_consume_(p, 1u);
    }
    p->buf[p->idx++] = c;
    return szlink_frame_parse_next(p, msg, lcid, sec);
}

#endif /* SZLINK_FRAME_H */
