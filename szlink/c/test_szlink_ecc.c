/* Unit tests for szlink_ecc.h. Build: gcc -std=c99 -Wall -Wextra -O2 -I. test_szlink_ecc.c */
#define SZLINK_ECC_IMPLEMENTATION
#include "szlink_ecc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static uint32_t rng_state = 12345u;
static uint32_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

/* Corrupt `count` distinct bytes of buf[0..len). */
static void corrupt(uint8_t *buf, size_t len, unsigned count)
{
    uint8_t hit[1024] = {0};
    while (count) {
        size_t p = rnd() % len;
        if (!hit[p]) {
            hit[p] = 1;
            buf[p] ^= (uint8_t)(1 + rnd() % 255);
            count--;
        }
    }
}

/* Golden vector shared with szlink/python/tests/test_ecc.py */
static void test_golden(void)
{
    static const uint8_t expected_hdr[] = {0xec, 0x28, 0x00, 0x84, 0x0e, 0xb1, 0xff};
    static const uint8_t expected_tail[] = {0x5b, 0x71, 0x5e, 0xaa, 0xf0, 0xb4, 0x89, 0x13,
                                            0xcb, 0xdd, 0x69, 0xe4, 0x9a, 0xf5, 0x29, 0xdd};
    uint8_t payload[40], out[128];
    int i, n;
    for (i = 0; i < 40; i++) {
        payload[i] = (uint8_t)i;
    }
    n = szlink_ecc_encode(payload, 40, 16, out, sizeof(out));
    CHECK(n == 7 + 40 + 16);
    CHECK(memcmp(out, expected_hdr, 7) == 0);
    CHECK(memcmp(out + 7, payload, 40) == 0);
    CHECK(memcmp(out + 47, expected_tail, 16) == 0);
}

static void test_rs_random(void)
{
    static const uint8_t nsyms[] = {2, 4, 16, 32, 64};
    uint8_t data[255], cw[255];
    size_t t, s;
    for (s = 0; s < sizeof(nsyms); s++) {
        uint8_t nsym = nsyms[s];
        for (t = 0; t < 1000; t++) {
            size_t len = 1 + rnd() % (255u - nsym), i;
            unsigned nerr = rnd() % (nsym / 2u + 1u);
            int r;
            for (i = 0; i < len; i++) {
                data[i] = (uint8_t)rnd();
            }
            CHECK(szlink_rs_encode(data, len, nsym, cw) == (int)(len + nsym));
            if (nerr > len + nsym) {
                nerr = (unsigned)(len + nsym);
            }
            corrupt(cw, len + nsym, nerr);
            r = szlink_rs_decode(cw, len + nsym, nsym);
            CHECK(r == (int)nerr);
            CHECK(memcmp(cw, data, len) == 0);
        }
    }
}

static void test_too_many_errors_detected(void)
{
    uint8_t data[200], cw[255];
    int t, undetected = 0;
    for (t = 0; t < 500; t++) {
        size_t i;
        int r;
        for (i = 0; i < sizeof(data); i++) {
            data[i] = (uint8_t)rnd();
        }
        szlink_rs_encode(data, sizeof(data), 16, cw);
        corrupt(cw, sizeof(data) + 16, 9 + rnd() % 8);
        r = szlink_rs_decode(cw, sizeof(data) + 16, 16);
        if (r >= 0 && memcmp(cw, data, sizeof(data)) != 0) {
            undetected++;
        }
        CHECK(!(r >= 0 && memcmp(cw, data, sizeof(data)) == 0 && r < 9));
    }
    /* Miscorrection is possible but must be rare. */
    CHECK(undetected < 5);
}

static void test_frame_roundtrip(void)
{
    uint8_t payload[600], frame[1024], out[600];
    int t;
    for (t = 0; t < 300; t++) {
        size_t len = 1 + rnd() % sizeof(payload), i, blocks, k = 255 - 16, b;
        int n, corrected = -1, r;
        for (i = 0; i < len; i++) {
            payload[i] = (uint8_t)rnd();
        }
        n = szlink_ecc_encode(payload, len, 16, frame, sizeof(frame));
        CHECK(n == (int)szlink_ecc_encoded_length(len, 16));
        CHECK(szlink_ecc_frame_length(frame, (size_t)n, 16) == n);
        /* up to 2 errors in the header, up to 8 per body block */
        corrupt(frame, 7, rnd() % 3);
        blocks = (len + k - 1) / k;
        for (b = 0; b < blocks; b++) {
            size_t off = 7 + b * 255;
            size_t blen = (b == blocks - 1) ? (size_t)n - off : 255;
            corrupt(frame + off, blen, rnd() % 9);
        }
        r = szlink_ecc_decode(frame, (size_t)n, 16, out, sizeof(out), &corrected);
        CHECK(r == (int)len);
        CHECK(corrected >= 0);
        CHECK(memcmp(out, payload, len) == 0);
    }
}

static void test_bad_params(void)
{
    uint8_t buf[300] = {0};
    CHECK(szlink_rs_encode(buf, 10, 3, buf) == SZLINK_ECC_ERR_PARAM);
    CHECK(szlink_rs_encode(buf, 250, 16, buf) == SZLINK_ECC_ERR_PARAM);
    CHECK(szlink_ecc_encode(buf, 10, 16, buf, 10) == SZLINK_ECC_ERR_PARAM);
    CHECK(szlink_ecc_frame_length(buf, 3, 16) == SZLINK_ECC_ERR_SHORT);
    CHECK(szlink_ecc_frame_length(buf, 7, 16) < 0); /* all zeros: bad magic */
}

int main(void)
{
    test_golden();
    test_rs_random();
    test_too_many_errors_detected();
    test_frame_roundtrip();
    test_bad_params();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("szlink_ecc C tests: all passed\n");
    return 0;
}
