/*
 * Tests for the SZ-Link frame layer (szlink_frame.h) on top of the generated,
 * szlink-prefixed spacezet dialect. Built and run by scripts/test_szlink.sh.
 */
#include "spacezet/szlink.h"
#include "szlink_frame.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,   \
                    #cond);                                                    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* Feed a buffer into the parser; return number of frames completed. */
static int feed(szlink_frame_parser_t *p, const uint8_t *buf, size_t len,
                szlink_message_t *msg, uint8_t *lcid, uint8_t *sec)
{
    int frames = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        if (szlink_frame_parse_char(p, buf[i], msg, lcid, sec)) {
            frames++;
        }
    }
    return frames;
}

static void test_rc_cmd_roundtrip(void)
{
    szlink_message_t tx, rx;
    szlink_sz_rc_cmd_t cmd;
    szlink_frame_parser_t p;
    uint8_t buf[SZLINK_FRAME_MAX_LEN];
    uint8_t lcid = 0xFF, sec = 0xFF;
    uint16_t n;

    szlink_msg_sz_rc_cmd_pack(42, 1, &tx, 1, 1, -1200, 3400, 0, 7500);
    n = szlink_frame_serialize(buf, &tx, SZ_LCID_RC, 0);

    CHECK(n == SZLINK_FRAME_OVERHEAD + tx.len);
    CHECK(buf[0] == SZLINK_FRAME_STX);
    CHECK(buf[1] == tx.len);
    CHECK(buf[2] == SZ_LCID_RC);
    CHECK(buf[4] == 42 && buf[5] == 1);
    CHECK((buf[6] | (buf[7] << 8) | ((uint32_t)buf[8] << 16)) == SZLINK_MSG_ID_SZ_RC_CMD);
    CHECK(buf[SZLINK_FRAME_HEADER_LEN + tx.len] == 0); /* SEC */

    szlink_frame_parser_init(&p);
    CHECK(feed(&p, buf, n, &rx, &lcid, &sec) == 1);
    CHECK(lcid == SZ_LCID_RC);
    CHECK(sec == 0);
    CHECK(rx.msgid == SZLINK_MSG_ID_SZ_RC_CMD);
    CHECK(rx.sysid == 42 && rx.compid == 1);

    szlink_msg_sz_rc_cmd_decode(&rx, &cmd);
    CHECK(cmd.target_system == 1 && cmd.target_component == 1);
    CHECK(cmd.roll == -1200 && cmd.pitch == 3400 && cmd.yaw == 0);
    CHECK(cmd.throttle == 7500);
    CHECK(p.rx_ok == 1 && p.crc_errors == 0);
}

static void test_standard_mavlink_message_on_telemetry(void)
{
    szlink_message_t tx, rx;
    szlink_heartbeat_t hb;
    szlink_frame_parser_t p;
    uint8_t buf[SZLINK_FRAME_MAX_LEN];
    uint8_t lcid = 0, sec = 0;
    uint16_t n;

    szlink_msg_heartbeat_pack(1, 1, &tx, MAV_TYPE_QUADROTOR, MAV_AUTOPILOT_GENERIC,
                              MAV_MODE_FLAG_SAFETY_ARMED, 0, MAV_STATE_ACTIVE);
    n = szlink_frame_serialize(buf, &tx, SZ_LCID_TELEMETRY, SZ_SEC_FLAGS_FEC);
    szlink_frame_parser_init(&p);
    CHECK(feed(&p, buf, n, &rx, &lcid, &sec) == 1);
    CHECK(lcid == SZ_LCID_TELEMETRY);
    CHECK(sec == SZ_SEC_FLAGS_FEC);
    szlink_msg_heartbeat_decode(&rx, &hb);
    CHECK(hb.type == MAV_TYPE_QUADROTOR);
    CHECK(hb.base_mode == MAV_MODE_FLAG_SAFETY_ARMED);
    CHECK(hb.system_status == MAV_STATE_ACTIVE);
}

static void test_video_pkt_full_payload(void)
{
    szlink_message_t tx, rx;
    szlink_sz_video_pkt_t pkt, out;
    szlink_frame_parser_t p;
    uint8_t buf[SZLINK_FRAME_MAX_LEN];
    uint8_t lcid = 0, sec = 0;
    uint16_t n;
    int i;

    memset(&pkt, 0, sizeof(pkt));
    pkt.frame_seq = 0xBEEF;
    pkt.frag_index = 3;
    pkt.frag_count = 9;
    pkt.codec = SZ_VIDEO_CODEC_H265;
    pkt.flags = SZ_VIDEO_PKT_FLAGS_KEYFRAME | SZ_VIDEO_PKT_FLAGS_NAL_END;
    pkt.len = 248;
    for (i = 0; i < 248; i++) {
        pkt.data[i] = (uint8_t)(i * 7 + 1);
    }
    szlink_msg_sz_video_pkt_encode(7, 100, &tx, &pkt);
    CHECK(tx.len == SZLINK_MSG_ID_SZ_VIDEO_PKT_LEN);
    n = szlink_frame_serialize(buf, &tx, SZ_LCID_VIDEO, SZ_SEC_FLAGS_ENCRYPTED);
    CHECK(n == SZLINK_FRAME_MAX_LEN);

    szlink_frame_parser_init(&p);
    CHECK(feed(&p, buf, n, &rx, &lcid, &sec) == 1);
    CHECK(lcid == SZ_LCID_VIDEO && sec == SZ_SEC_FLAGS_ENCRYPTED);
    memset(&out, 0, sizeof(out));
    szlink_msg_sz_video_pkt_decode(&rx, &out);
    /* Compare field by field: the struct may have trailing padding. */
    CHECK(out.frame_seq == pkt.frame_seq);
    CHECK(out.frag_index == pkt.frag_index && out.frag_count == pkt.frag_count);
    CHECK(out.codec == pkt.codec && out.flags == pkt.flags && out.len == pkt.len);
    CHECK(memcmp(out.data, pkt.data, sizeof(pkt.data)) == 0);
}

static void test_corruption_is_rejected(void)
{
    szlink_message_t tx, rx;
    szlink_frame_parser_t p;
    uint8_t buf[SZLINK_FRAME_MAX_LEN];
    uint8_t lcid, sec;
    uint16_t n, i;

    szlink_msg_sz_rc_cmd_pack(1, 1, &tx, 1, 1, 10, 20, 30, 40);
    n = szlink_frame_serialize(buf, &tx, SZ_LCID_RC, 0);
    /* Flipping any byte after STX (including LCID and SEC) must fail the CRC. */
    for (i = 1; i < n; i++) {
        uint8_t bad[SZLINK_FRAME_MAX_LEN];
        memcpy(bad, buf, n);
        bad[i] ^= 0x10;
        szlink_frame_parser_init(&p);
        CHECK(feed(&p, bad, n, &rx, &lcid, &sec) == 0);
    }
}

static void test_stream_with_garbage_and_resync(void)
{
    szlink_message_t tx, rx;
    szlink_frame_parser_t p;
    uint8_t stream[4 * SZLINK_FRAME_MAX_LEN];
    uint8_t lcid, sec;
    size_t len = 0;
    uint16_t n;
    int k;

    /* Leading garbage, including a fake STX with a bogus length. */
    stream[len++] = 0x00;
    stream[len++] = SZLINK_FRAME_STX;
    stream[len++] = 0x03;
    stream[len++] = 0x55;
    for (k = 0; k < 3; k++) {
        szlink_msg_sz_rc_cmd_pack(1, 1, &tx, 1, 1, (int16_t)k, 0, 0, 0);
        n = szlink_frame_serialize(stream + len, &tx, SZ_LCID_RC, 0);
        len += n;
    }
    szlink_frame_parser_init(&p);
    CHECK(feed(&p, stream, len, &rx, &lcid, &sec) == 3);
    CHECK(p.rx_ok == 3);
}

static void test_frames_after_long_false_start(void)
{
    /* A fake STX with a large LEN makes the parser buffer several real frames
       before the fake frame fails; every one of them must still be decoded. */
    szlink_message_t tx, rx;
    szlink_frame_parser_t p;
    uint8_t stream[4 * SZLINK_FRAME_MAX_LEN];
    uint8_t lcid, sec;
    size_t len = 0;
    int k;

    stream[len++] = SZLINK_FRAME_STX;
    stream[len++] = 200;
    for (k = 0; k < 12; k++) {
        szlink_msg_sz_rc_cmd_pack(1, 1, &tx, 1, 1, (int16_t)k, 0, 0, 0);
        len += szlink_frame_serialize(stream + len, &tx, SZ_LCID_RC, 0);
    }
    szlink_frame_parser_init(&p);
    CHECK(feed(&p, stream, len, &rx, &lcid, &sec) == 12);
    CHECK(p.rx_ok == 12);
}

static void test_oversized_len_dropped(void)
{
    szlink_message_t tx, rx;
    szlink_frame_parser_t p;
    uint8_t buf[SZLINK_FRAME_MAX_LEN];
    uint8_t lcid, sec;
    uint16_t n;

    szlink_msg_sz_rc_cmd_pack(1, 1, &tx, 1, 1, 0, 0, 0, 0);
    tx.len = SZLINK_MSG_ID_SZ_RC_CMD_LEN + 1; /* CRC-valid, but longer than the message */
    n = szlink_frame_serialize(buf, &tx, SZ_LCID_RC, 0);
    szlink_frame_parser_init(&p);
    CHECK(feed(&p, buf, n, &rx, &lcid, &sec) == 0);
    CHECK(p.len_errors == 1 && p.rx_ok == 0);
}

static void test_unknown_msgid_dropped(void)
{
    szlink_message_t tx, rx;
    szlink_frame_parser_t p;
    uint8_t buf[SZLINK_FRAME_MAX_LEN];
    uint8_t lcid, sec;
    uint16_t n;

    szlink_msg_sz_rc_cmd_pack(1, 1, &tx, 1, 1, 0, 0, 0, 0);
    n = szlink_frame_serialize(buf, &tx, SZ_LCID_RC, 0);
    buf[8] = 0x7F; /* msgid 0x7Fxxxx does not exist */
    szlink_frame_parser_init(&p);
    CHECK(feed(&p, buf, n, &rx, &lcid, &sec) == 0);
    CHECK(p.unknown_msgid == 1);
}

static void test_wide_sysid_rejected(void)
{
    szlink_message_t tx;
    uint8_t buf[SZLINK_FRAME_MAX_LEN];
    szlink_msg_sz_rc_cmd_pack(1, 1, &tx, 1, 1, 0, 0, 0, 0);
    tx.sysid = 300; /* SZ-Link SYSID is one byte */
    CHECK(szlink_frame_serialize(buf, &tx, SZ_LCID_RC, 0) == 0);
}

int main(void)
{
    test_rc_cmd_roundtrip();
    test_standard_mavlink_message_on_telemetry();
    test_video_pkt_full_payload();
    test_corruption_is_rejected();
    test_stream_with_garbage_and_resync();
    test_frames_after_long_false_start();
    test_oversized_len_dropped();
    test_unknown_msgid_dropped();
    test_wide_sysid_rejected();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("szlink frame tests: all passed\n");
    return 0;
}
