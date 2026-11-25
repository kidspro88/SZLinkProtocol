/**
 * @file szlink_frame.h
 * @brief SZ-Link frame layer: LCID + SEC framing on top of MAVLink 2 messages.
 *
 * Wire format (all multi-byte fields little-endian):
 *
 *   STX | LEN | LCID | SEQ | SYSID | COMPID | MSGID (3) | PAYLOAD (LEN) | SEC | CRC (2)
 *   0xFD  1B    1B     1B    1B      1B       3B          0..255 B        1B    2B
 *
 * - LCID: logical channel (SZ_LCID: 0 = RC, 1 = Telemetry, 2 = Video).
 * - SEC:  security flags (SZ_SEC_FLAGS: bit 0 encrypted, bit 1 FEC).
 * - CRC:  CRC-16/MCRF4XX (the MAVLink X.25 CRC, CCITT polynomial 0x1021,
 *         reflected) over LEN..SEC followed by the message's CRC_EXTRA byte,
 *         exactly as MAVLink 2 does, so a peer with a different message
 *         definition rejects the frame.
 * - PAYLOAD uses MAVLink 2 payload encoding, including trailing-zero trimming.
 *
 * Include after the generated dialect header, e.g.:
 *
 *   #include "spacezet/szlink.h"
 *   #include "szlink_frame.h"
 *
 * Messages are built with the generated szlink_msg_*_pack()/encode() helpers
 * and decoded with szlink_msg_*_decode(); this header only moves them on and
 * off the wire. No dynamic allocation; one parser instance per link.
 */
#ifndef SZLINK_FRAME_H
#define SZLINK_FRAME_H

#include <stdint.h>
#include <string.h>

#ifndef SZLINK_VERSION
#error "Include the generated dialect header (e.g. spacezet/szlink.h) before szlink_frame.h"
#endif

#define SZLINK_FRAME_STX        0xFDu
#define SZLINK_FRAME_HEADER_LEN 9u  /* STX LEN LCID SEQ SYSID COMPID MSGID[3] */
#define SZLINK_FRAME_TRAILER_LEN 3u /* SEC CRC[2] */
#define SZLINK_FRAME_OVERHEAD   (SZLINK_FRAME_HEADER_LEN + SZLINK_FRAME_TRAILER_LEN)
#define SZLINK_FRAME_MAX_LEN    (SZLINK_FRAME_OVERHEAD + 255u)

typedef struct {
    uint8_t buf[SZLINK_FRAME_MAX_LEN];
    uint16_t idx;           /* bytes buffered for the current frame */
    uint32_t rx_ok;         /* frames accepted */
    uint32_t crc_errors;    /* frames dropped for a bad CRC */
    uint32_t unknown_msgid; /* frames dropped because the msgid is unknown */
    uint32_t len_errors;    /* frames dropped because LEN exceeds the message's max length */
} szlink_frame_parser_t;

static inline uint16_t szlink_frame_crc(const uint8_t *frame, uint8_t len, uint8_t crc_extra)
{
    uint16_t crc;
    /* LEN .. SEC */
    crc_init(&crc);
    crc_accumulate_buffer(&crc, (const char *)frame + 1,
                          (uint16_t)(SZLINK_FRAME_HEADER_LEN - 1u + len + 1u));
    crc_accumulate(crc_extra, &crc);
    return crc;
}

/**
 * Serialize a packed message into an SZ-Link frame.
 *
 * @param buf  output buffer of at least SZLINK_FRAME_MAX_LEN bytes
 * @param msg  message built by a generated szlink_msg_*_pack/encode helper
 * @param lcid logical channel (SZ_LCID)
 * @param sec  security flags (SZ_SEC_FLAGS)
 * @return frame length in bytes, or 0 if the message cannot be sent
 *         (unknown msgid, or a SYSID that does not fit in one byte)
 */
static inline uint16_t szlink_frame_serialize(uint8_t *buf, const szlink_message_t *msg,
                                              uint8_t lcid, uint8_t sec)
{
    const szlink_msg_entry_t *e = szlink_get_msg_entry(msg->msgid);
    uint16_t crc;
    if (e == NULL || msg->sysid > 0xFFu) {
        return 0;
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
    buf[SZLINK_FRAME_HEADER_LEN + msg->len] = sec;
    crc = szlink_frame_crc(buf, msg->len, e->crc_extra);
    buf[SZLINK_FRAME_HEADER_LEN + msg->len + 1u] = (uint8_t)(crc & 0xFFu);
    buf[SZLINK_FRAME_HEADER_LEN + msg->len + 2u] = (uint8_t)(crc >> 8);
    return (uint16_t)(SZLINK_FRAME_OVERHEAD + msg->len);
}

static inline void szlink_frame_parser_init(szlink_frame_parser_t *p)
{
    memset(p, 0, sizeof(*p));
}

/* Validate the complete frame in p->buf. Returns 1 and fills the outputs if valid. */
static inline int szlink_frame_check_(szlink_frame_parser_t *p, szlink_message_t *msg,
                                      uint8_t *lcid, uint8_t *sec)
{
    const uint8_t *b = p->buf;
    uint8_t len = b[1];
    uint32_t msgid = (uint32_t)b[6] | ((uint32_t)b[7] << 8) | ((uint32_t)b[8] << 16);
    const szlink_msg_entry_t *e = szlink_get_msg_entry(msgid);
    uint16_t crc, rx_crc;

    if (e == NULL) {
        p->unknown_msgid++;
        return 0;
    }
    if (len > e->max_msg_len) {
        p->len_errors++;
        return 0;
    }
    crc = szlink_frame_crc(b, len, e->crc_extra);
    rx_crc = (uint16_t)(b[SZLINK_FRAME_HEADER_LEN + len + 1u] |
                        (b[SZLINK_FRAME_HEADER_LEN + len + 2u] << 8));
    if (crc != rx_crc) {
        p->crc_errors++;
        return 0;
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
    *sec = b[SZLINK_FRAME_HEADER_LEN + len];
    p->rx_ok++;
    return 1;
}

/* Drop the first n buffered bytes, then any bytes before the next STX. */
static inline void szlink_frame_consume_(szlink_frame_parser_t *p, uint16_t n)
{
    uint16_t k = n;
    while (k < p->idx && p->buf[k] != SZLINK_FRAME_STX) {
        k++;
    }
    memmove(p->buf, &p->buf[k], (size_t)(p->idx - k));
    p->idx = (uint16_t)(p->idx - k);
}

/**
 * Feed one received byte.
 *
 * @return 1 when a complete, CRC-valid frame has been decoded into
 *         msg / lcid / sec; 0 otherwise.
 *
 * After a bad frame the parser rescans the buffered bytes for the next STX,
 * so a frame that starts inside a corrupted one is not lost. Bytes buffered
 * after a decoded frame are kept: if they already hold further complete
 * frames, those are returned by the following calls, one per call. This is
 * iterative and uses no extra stack beyond a few locals.
 */
static inline int szlink_frame_parse_char(szlink_frame_parser_t *p, uint8_t c,
                                          szlink_message_t *msg, uint8_t *lcid, uint8_t *sec)
{
    if (p->idx == 0u && c != SZLINK_FRAME_STX) {
        return 0;
    }
    p->buf[p->idx++] = c;

    for (;;) {
        uint16_t need;
        if (p->idx < 2u) {
            return 0;
        }
        need = (uint16_t)(SZLINK_FRAME_OVERHEAD + p->buf[1]);
        if (p->idx < need) {
            return 0;
        }
        /* A complete frame is buffered, possibly followed by more bytes. */
        if (szlink_frame_check_(p, msg, lcid, sec)) {
            szlink_frame_consume_(p, need);
            return 1;
        }
        /* Bad frame: restart at the next STX after the current one. */
        szlink_frame_consume_(p, 1u);
        /* The shifted bytes may already hold a complete frame: loop. */
    }
}

#endif /* SZLINK_FRAME_H */
