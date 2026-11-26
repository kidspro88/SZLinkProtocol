/**
 * @file szlink_ecc.h
 * @brief SZ-Link FEC: header-only Reed-Solomon envelope for SZ-Link frames.
 *
 * Byte-for-byte compatible with szlink/python/szlink/ecc.py, which documents
 * the wire format. SZ-Link sends video frames (SEC_FEC set) in this envelope.
 *
 * Usage: in exactly one .c file, `#define SZLINK_ECC_IMPLEMENTATION` before
 * including this header. No dynamic allocation; tables are built lazily on
 * first use (call szlink_ecc_init() up front on multi-threaded targets).
 */
#ifndef SZLINK_ECC_H
#define SZLINK_ECC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SZLINK_ECC_MAGIC        0xECu
#define SZLINK_ECC_HEADER_DATA  3u
#define SZLINK_ECC_HEADER_NSYM  4u
#define SZLINK_ECC_HEADER_LEN   (SZLINK_ECC_HEADER_DATA + SZLINK_ECC_HEADER_NSYM)
#define SZLINK_ECC_DEFAULT_NSYM 16u
#define SZLINK_ECC_MAX_NSYM     64u

/** Return codes (negative = error). */
#define SZLINK_ECC_ERR_PARAM      (-1)
#define SZLINK_ECC_ERR_UNCORRECTABLE (-2)
#define SZLINK_ECC_ERR_SHORT      (-3)
#define SZLINK_ECC_ERR_MAGIC      (-4)

void szlink_ecc_init(void);

/** Encode one RS codeword: writes len + nsym bytes to out. Returns length or <0. */
int szlink_rs_encode(const uint8_t *data, size_t len, uint8_t nsym, uint8_t *out);

/** Correct a codeword in place. Returns number of corrected bytes or <0. */
int szlink_rs_decode(uint8_t *codeword, size_t len, uint8_t nsym);

/** Encoded size of a payload of payload_len bytes. */
size_t szlink_ecc_encoded_length(size_t payload_len, uint8_t nsym);

/** Encode payload into an SZ-Link ECC frame. Returns bytes written or <0. */
int szlink_ecc_encode(const uint8_t *payload, size_t payload_len, uint8_t nsym,
                      uint8_t *out, size_t out_size);

/**
 * Decode an SZ-Link ECC frame. `frame` is modified (corrected) in place.
 * On success returns payload length, copies the payload into `payload`, and
 * stores the number of corrected bytes in *corrected (if not NULL).
 */
int szlink_ecc_decode(uint8_t *frame, size_t frame_len, uint8_t nsym,
                      uint8_t *payload, size_t payload_size, int *corrected);

/**
 * Peek the header of a (possibly corrupted) frame. Returns total encoded frame
 * length (header + body) or <0 if no valid header starts at `buf`.
 */
int szlink_ecc_frame_length(const uint8_t *buf, size_t len, uint8_t nsym);

#ifdef __cplusplus
}
#endif

#ifdef SZLINK_ECC_IMPLEMENTATION

#include <string.h>

static uint8_t szlink_gf_exp[512];
static uint8_t szlink_gf_log[256];
static int szlink_gf_ready = 0;

void szlink_ecc_init(void)
{
    unsigned x = 1, i;
    if (szlink_gf_ready) {
        return;
    }
    for (i = 0; i < 255; i++) {
        szlink_gf_exp[i] = (uint8_t)x;
        szlink_gf_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100u) {
            x ^= 0x11Du;
        }
    }
    for (i = 255; i < 512; i++) {
        szlink_gf_exp[i] = szlink_gf_exp[i - 255];
    }
    szlink_gf_ready = 1;
}

static uint8_t szlink_gf_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    return szlink_gf_exp[szlink_gf_log[a] + szlink_gf_log[b]];
}

static uint8_t szlink_gf_div(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    return szlink_gf_exp[(szlink_gf_log[a] + 255 - szlink_gf_log[b]) % 255];
}

/* Polynomials: highest degree first. */
static uint8_t szlink_poly_eval(const uint8_t *p, size_t len, uint8_t x)
{
    uint8_t y = p[0];
    size_t i;
    for (i = 1; i < len; i++) {
        y = (uint8_t)(szlink_gf_mul(y, x) ^ p[i]);
    }
    return y;
}

static void szlink_rs_generator(uint8_t nsym, uint8_t *g /* nsym + 1 */)
{
    size_t len = 1, i, j;
    g[0] = 1;
    for (i = 0; i < nsym; i++) {
        /* g = g * (x + alpha^i) */
        uint8_t root = szlink_gf_exp[i];
        g[len] = 0;
        for (j = len; j > 0; j--) {
            g[j] ^= szlink_gf_mul(g[j - 1], root);
        }
        len++;
    }
}

int szlink_rs_encode(const uint8_t *data, size_t len, uint8_t nsym, uint8_t *out)
{
    uint8_t g[SZLINK_ECC_MAX_NSYM + 1];
    uint8_t rem[SZLINK_ECC_MAX_NSYM];
    size_t i, j;

    if (nsym < 2 || nsym > SZLINK_ECC_MAX_NSYM || (nsym & 1) || len + nsym > 255) {
        return SZLINK_ECC_ERR_PARAM;
    }
    szlink_ecc_init();
    szlink_rs_generator(nsym, g);
    memset(rem, 0, nsym);
    for (i = 0; i < len; i++) {
        uint8_t coef = (uint8_t)(data[i] ^ rem[0]);
        memmove(rem, rem + 1, (size_t)nsym - 1);
        rem[nsym - 1] = 0;
        if (coef) {
            for (j = 0; j < nsym; j++) {
                rem[j] ^= szlink_gf_mul(g[j + 1], coef);
            }
        }
    }
    if (out != data) {
        memmove(out, data, len);
    }
    memcpy(out + len, rem, nsym);
    return (int)(len + nsym);
}

int szlink_rs_decode(uint8_t *msg, size_t n, uint8_t nsym)
{
    uint8_t synd[SZLINK_ECC_MAX_NSYM + 1]; /* synd[0] = 0 padding */
    uint8_t err_loc[SZLINK_ECC_MAX_NSYM + 2], old_loc[SZLINK_ECC_MAX_NSYM + 2];
    uint8_t tmp[SZLINK_ECC_MAX_NSYM + 2];
    uint8_t loc[SZLINK_ECC_MAX_NSYM / 2 + 1], omega[SZLINK_ECC_MAX_NSYM / 2 + 1];
    uint8_t coef_pos[SZLINK_ECC_MAX_NSYM / 2];
    size_t err_pos[SZLINK_ECC_MAX_NSYM / 2];
    size_t el = 1, ol = 1, i, j, k, n_err, found = 0;
    int any = 0;

    if (nsym < 2 || nsym > SZLINK_ECC_MAX_NSYM || (nsym & 1) || n <= nsym || n > 255) {
        return SZLINK_ECC_ERR_PARAM;
    }
    szlink_ecc_init();

    synd[0] = 0;
    for (i = 0; i < nsym; i++) {
        synd[i + 1] = szlink_poly_eval(msg, n, szlink_gf_exp[i]);
        any |= synd[i + 1];
    }
    if (!any) {
        return 0;
    }

    /* Berlekamp-Massey */
    err_loc[0] = 1;
    old_loc[0] = 1;
    for (i = 0; i < nsym; i++) {
        size_t K = i + 1;
        uint8_t delta = synd[K];
        for (j = 1; j < el; j++) {
            delta ^= szlink_gf_mul(err_loc[el - 1 - j], synd[K - j]);
        }
        old_loc[ol++] = 0;
        if (delta) {
            if (ol > el) {
                uint8_t inv = szlink_gf_div(1, delta);
                /* new_loc = old_loc * delta; old_loc = err_loc / delta */
                for (j = 0; j < ol; j++) {
                    tmp[j] = szlink_gf_mul(old_loc[j], delta);
                }
                for (j = 0; j < el; j++) {
                    old_loc[j] = szlink_gf_mul(err_loc[j], inv);
                }
                k = ol;
                ol = el;
                el = k;
                memcpy(err_loc, tmp, el);
            }
            /* err_loc += old_loc * delta (right-aligned) */
            for (j = 0; j < ol; j++) {
                err_loc[el - ol + j] ^= szlink_gf_mul(old_loc[j], delta);
            }
        }
        if (el > (size_t)nsym + 1u || ol > (size_t)nsym + 1u) {
            return SZLINK_ECC_ERR_UNCORRECTABLE;
        }
    }
    k = 0;
    while (k < el && err_loc[k] == 0) {
        k++;
    }
    n_err = el - k - 1;
    if (k >= el || n_err * 2 > nsym) {
        return SZLINK_ECC_ERR_UNCORRECTABLE;
    }
    memmove(err_loc, err_loc + k, n_err + 1);

    /* Chien search on the reversed locator */
    for (i = 0; i < n_err + 1; i++) {
        tmp[i] = err_loc[n_err - i];
    }
    for (i = 0; i < n; i++) {
        if (szlink_poly_eval(tmp, n_err + 1, szlink_gf_exp[i]) == 0) {
            if (found == n_err) {
                return SZLINK_ECC_ERR_UNCORRECTABLE;
            }
            err_pos[found] = n - 1 - i;
            coef_pos[found] = (uint8_t)i;
            found++;
        }
    }
    if (found != n_err) {
        return SZLINK_ECC_ERR_UNCORRECTABLE;
    }

    /* Errata locator: prod (alpha^p x + 1), highest degree first */
    loc[0] = 1;
    for (i = 0; i < n_err; i++) {
        uint8_t a = szlink_gf_exp[coef_pos[i]];
        /* loc = loc * (a x + 1): new[j] = a * loc[j] + loc[j - 1] */
        loc[i + 1] = 0;
        for (j = i + 1; j > 0; j--) {
            loc[j] = (uint8_t)(szlink_gf_mul(loc[j], a) ^ loc[j - 1]);
        }
        loc[0] = szlink_gf_mul(loc[0], a);
    }
    /* omega = last (n_err + 1) coefficients of reversed(synd) * loc */
    for (k = 0; k <= n_err; k++) {
        /* product index (nsym + n_err) - n_err + k = nsym + k */
        size_t idx = nsym + k;
        uint8_t s = 0;
        for (j = 0; j <= n_err; j++) {
            if (idx >= j && idx - j <= nsym) {
                /* reversed synd coefficient at (idx - j) is synd[nsym - (idx - j)] */
                s ^= szlink_gf_mul(synd[nsym - (idx - j)], loc[j]);
            }
        }
        omega[k] = s;
    }
    /* Forney */
    for (i = 0; i < n_err; i++) {
        uint8_t xi = szlink_gf_exp[coef_pos[i]];
        uint8_t xi_inv = szlink_gf_div(1, xi);
        uint8_t denom = 1, y;
        for (j = 0; j < n_err; j++) {
            if (j != i) {
                denom = szlink_gf_mul(denom,
                                      (uint8_t)(1 ^ szlink_gf_mul(xi_inv, szlink_gf_exp[coef_pos[j]])));
            }
        }
        if (denom == 0) {
            return SZLINK_ECC_ERR_UNCORRECTABLE;
        }
        y = szlink_gf_mul(xi, szlink_poly_eval(omega, n_err + 1, xi_inv));
        msg[err_pos[i]] ^= szlink_gf_div(y, denom);
    }
    for (i = 0; i < nsym; i++) {
        if (szlink_poly_eval(msg, n, szlink_gf_exp[i]) != 0) {
            return SZLINK_ECC_ERR_UNCORRECTABLE;
        }
    }
    return (int)n_err;
}

size_t szlink_ecc_encoded_length(size_t payload_len, uint8_t nsym)
{
    size_t k = 255u - nsym;
    size_t blocks = (payload_len + k - 1) / k;
    return SZLINK_ECC_HEADER_LEN + payload_len + blocks * nsym;
}

int szlink_ecc_encode(const uint8_t *payload, size_t payload_len, uint8_t nsym,
                      uint8_t *out, size_t out_size)
{
    uint8_t hdr[SZLINK_ECC_HEADER_DATA];
    size_t pos, k, off;
    if (nsym < 2 || nsym > SZLINK_ECC_MAX_NSYM || (nsym & 1) || payload_len > 0xFFFFu ||
        szlink_ecc_encoded_length(payload_len, nsym) > out_size) {
        return SZLINK_ECC_ERR_PARAM;
    }
    hdr[0] = SZLINK_ECC_MAGIC;
    hdr[1] = (uint8_t)(payload_len & 0xFFu);
    hdr[2] = (uint8_t)(payload_len >> 8);
    pos = (size_t)szlink_rs_encode(hdr, sizeof(hdr), SZLINK_ECC_HEADER_NSYM, out);
    k = 255u - nsym;
    for (off = 0; off < payload_len; off += k) {
        size_t dlen = payload_len - off < k ? payload_len - off : k;
        pos += (size_t)szlink_rs_encode(payload + off, dlen, nsym, out + pos);
    }
    return (int)pos;
}

static int szlink_ecc_header(uint8_t *hdr, size_t *payload_len)
{
    int r = szlink_rs_decode(hdr, SZLINK_ECC_HEADER_LEN, SZLINK_ECC_HEADER_NSYM);
    if (r < 0) {
        return r;
    }
    if (hdr[0] != SZLINK_ECC_MAGIC) {
        return SZLINK_ECC_ERR_MAGIC;
    }
    *payload_len = (size_t)hdr[1] | ((size_t)hdr[2] << 8);
    return r;
}

int szlink_ecc_frame_length(const uint8_t *buf, size_t len, uint8_t nsym)
{
    uint8_t hdr[SZLINK_ECC_HEADER_LEN];
    size_t plen;
    int r;
    if (len < SZLINK_ECC_HEADER_LEN) {
        return SZLINK_ECC_ERR_SHORT;
    }
    memcpy(hdr, buf, sizeof(hdr));
    r = szlink_ecc_header(hdr, &plen);
    if (r < 0) {
        return r;
    }
    return (int)szlink_ecc_encoded_length(plen, nsym);
}

int szlink_ecc_decode(uint8_t *frame, size_t frame_len, uint8_t nsym,
                      uint8_t *payload, size_t payload_size, int *corrected)
{
    size_t plen, pos, off, k;
    int fixed, r;
    if (nsym < 2 || nsym > SZLINK_ECC_MAX_NSYM || (nsym & 1)) {
        return SZLINK_ECC_ERR_PARAM;
    }
    if (frame_len < SZLINK_ECC_HEADER_LEN) {
        return SZLINK_ECC_ERR_SHORT;
    }
    fixed = szlink_ecc_header(frame, &plen);
    if (fixed < 0) {
        return fixed;
    }
    if (frame_len < szlink_ecc_encoded_length(plen, nsym)) {
        return SZLINK_ECC_ERR_SHORT;
    }
    if (plen > payload_size) {
        return SZLINK_ECC_ERR_PARAM;
    }
    k = 255u - nsym;
    pos = SZLINK_ECC_HEADER_LEN;
    for (off = 0; off < plen; off += k) {
        size_t dlen = plen - off < k ? plen - off : k;
        r = szlink_rs_decode(frame + pos, dlen + nsym, nsym);
        if (r < 0) {
            return r;
        }
        fixed += r;
        memcpy(payload + off, frame + pos, dlen);
        pos += dlen + nsym;
    }
    if (corrected) {
        *corrected = fixed;
    }
    return (int)plen;
}

#endif /* SZLINK_ECC_IMPLEMENTATION */
#endif /* SZLINK_ECC_H */
