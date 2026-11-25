/**
 * @file szlink_sec.h
 * @brief SZ-Link security layer: Noise_IK handshake, 30 s key ratchet,
 *        per-channel ChaCha20-Poly1305 keys and anti-replay.
 *
 * Byte-for-byte compatible with szlink/python/szlink/{crypto,session}.py.
 * The protocol is described in szlink/README.md ("Security").
 *
 * - Handshake: Noise_IK_25519_ChaChaPoly_BLAKE2b, prologue "SZ-Link v1".
 *   The ground station is the initiator and knows the vehicle's static
 *   X25519 public key; the vehicle accepts only its paired ground station.
 *   KEX_INIT (104 bytes) carries a strictly increasing timestamp so a
 *   replayed KEX_INIT is rejected; KEX_RESP is 48 bytes.
 * - Ratchet: each direction has a chain key; every 30 s (no packets on air)
 *   chain' = HKDF-Expand(chain, "SZL chain") and the old chain is wiped.
 *   Per-LCID keys of an epoch are HKDF-Expand(chain, "SZL lcid" || lcid).
 *   The initiator runs a new handshake every 10 minutes.
 * - Frames: ChaCha20-Poly1305 (RFC 8439), nonce = epoch (u32 LE) | lcid |
 *   0 0 0 | counter (u32 LE). The counter is implicit: only its low byte is
 *   sent, in the SEQ field. AD = header (STX..MSGID) || SEC, plus the
 *   payload for signed-only frames. Tag is 8 bytes on LCID RC, else 16.
 *
 * Depends on Monocypher 3.1.x (crypto_x25519, crypto_blake2b_*,
 * crypto_ietf_chacha20_ctr, crypto_poly1305_*). No dynamic allocation, no
 * clock and no RNG: the caller passes a monotonic millisecond time and
 * random ephemeral keys.
 *
 * Usage: in exactly one translation unit
 *     #define SZLINK_SEC_IMPLEMENTATION
 *     #include "szlink_sec.h"
 */
#ifndef SZLINK_SEC_H
#define SZLINK_SEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SEC byte (SZ_SEC_FLAGS) */
#define SZLINK_SEC_ENCRYPTED   0x01u
#define SZLINK_SEC_EPOCH_MASK  0x06u
#define SZLINK_SEC_EPOCH_SHIFT 1u
#define SZLINK_SEC_FEC         0x08u
#define SZLINK_SEC_SIGNED      0x10u
#define SZLINK_SEC_PROTECTED   (SZLINK_SEC_ENCRYPTED | SZLINK_SEC_SIGNED)

#define SZLINK_SEC_NUM_LCID      3u
#define SZLINK_SEC_LCID_RC       0u
#define SZLINK_SEC_KEY_LEN       32u
#define SZLINK_SEC_TAG_MAX       16u
#define SZLINK_SEC_HEADER_LEN    9u
#define SZLINK_SEC_KEX_INIT_LEN  104u
#define SZLINK_SEC_KEX_RESP_LEN  48u

#define SZLINK_SEC_EPOCH_MS          30000u
#define SZLINK_SEC_REKEY_MS          600000u
#define SZLINK_SEC_SESSION_MAX_MS    720000u
#define SZLINK_SEC_PREV_GRACE_MS     5000u
#define SZLINK_SEC_KEX_RETRY_MS      1000u
#define SZLINK_SEC_RX_IDLE_REKEY_MS  5000u
#define SZLINK_SEC_REPLAY_WINDOW     64u
#define SZLINK_SEC_COUNTER_SEARCH    16u

enum {
    SZLINK_SEC_INITIATOR = 0, /* ground station */
    SZLINK_SEC_RESPONDER = 1  /* vehicle */
};

/* return codes (negative = error) */
#define SZLINK_SEC_OK              0
#define SZLINK_SEC_ERR_AUTH       (-1)
#define SZLINK_SEC_ERR_NO_SESSION (-2)
#define SZLINK_SEC_ERR_PARAM      (-3)
#define SZLINK_SEC_ERR_REPLAY     (-4)

typedef struct {
    uint64_t bits;     /* bit i set: counter (top - i) accepted */
    uint32_t top;      /* highest accepted counter */
    uint8_t has_top;
} szlink_sec_replay_t;

typedef struct {
    uint32_t epoch;
    uint8_t keys[SZLINK_SEC_NUM_LCID][SZLINK_SEC_KEY_LEN];
    szlink_sec_replay_t win[SZLINK_SEC_NUM_LCID];
} szlink_sec_epoch_t;

typedef struct {
    uint8_t valid;
    uint32_t start_ms;
    /* transmit chain */
    uint8_t tx_chain[SZLINK_SEC_KEY_LEN];
    uint32_t tx_epoch;
    uint8_t tx_keys[SZLINK_SEC_NUM_LCID][SZLINK_SEC_KEY_LEN];
    uint32_t tx_ctr[SZLINK_SEC_NUM_LCID];
    uint8_t tx_ctr_exhausted[SZLINK_SEC_NUM_LCID];
    /* receive chain: current epoch and the one before it */
    uint8_t rx_chain[SZLINK_SEC_KEY_LEN];
    szlink_sec_epoch_t rx_cur;
    szlink_sec_epoch_t rx_prev;
    uint8_t rx_has_prev;
} szlink_sec_session_t;

typedef struct {
    uint8_t ck[64];
    uint8_t h[64];
    uint8_t k[32];
    uint64_t n;
} szlink_sec_noise_t;

typedef struct {
    uint32_t auth_fail;
    uint32_t rekeys;
    uint32_t kex_replay;
    uint32_t kex_rejected;
} szlink_sec_stats_t;

typedef struct {
    uint8_t role;
    uint8_t s_priv[32];
    uint8_t s_pub[32];
    uint8_t peer_pub[32];
    uint8_t ss[32];          /* DH(static, peer static), cached */
    uint8_t ss_ok;
    szlink_sec_session_t cur;
    szlink_sec_session_t pending; /* responder: until the initiator proves it */
    szlink_sec_session_t prev;    /* RX only, for SZLINK_SEC_PREV_GRACE_MS */
    uint32_t prev_until_ms;
    /* initiator handshake in progress */
    szlink_sec_noise_t hs;
    uint8_t hs_e[32];
    uint8_t hs_active;
    uint32_t hs_sent_ms;
    /* responder: newest accepted KEX_INIT timestamp */
    uint64_t last_kex_ts;
    uint8_t have_kex_ts;
    /* last authenticated frame */
    uint32_t last_rx_ms;
    uint8_t have_rx;
    szlink_sec_stats_t stats;
} szlink_sec_t;

/** Set up one end. peer_pub is the other end's static X25519 public key. */
void szlink_sec_init(szlink_sec_t *s, uint8_t role, const uint8_t s_priv[32],
                     const uint8_t peer_pub[32]);
/** Wipe all key material. */
void szlink_sec_wipe(szlink_sec_t *s);

/**
 * Derive both static private keys from one 32-byte shared secret (the
 * MAVLink 2 signing key: SHA-256 of the passphrase given to
 * `signing setup` in MAVProxy, or set with SETUP_SIGNING). Lets a vehicle
 * and its ground station be paired with the key they already share.
 */
void szlink_sec_keys_from_secret(const uint8_t secret[32], uint8_t vehicle_priv[32],
                                 uint8_t ground_priv[32]);

/** Static public key of a private key. */
void szlink_sec_public_key(uint8_t pub[32], const uint8_t priv[32]);

/** Authentication tag length on a logical channel: 8 (RC) or 16. */
uint8_t szlink_sec_tag_len(uint8_t lcid);

/** Initiator: 1 if a KEX_INIT should be sent now. */
int szlink_sec_needs_kex(const szlink_sec_t *s, uint32_t now_ms);
/** Initiator: start a handshake. timestamp_us must increase on every call
 *  (also across restarts). Writes SZLINK_SEC_KEX_INIT_LEN bytes. */
int szlink_sec_kex_init(szlink_sec_t *s, const uint8_t eph_priv[32], uint64_t timestamp_us,
                        uint32_t now_ms, uint8_t out[SZLINK_SEC_KEX_INIT_LEN]);
/** Initiator: complete the handshake. */
int szlink_sec_handle_kex_resp(szlink_sec_t *s, const uint8_t in[SZLINK_SEC_KEX_RESP_LEN],
                               uint32_t now_ms);
/** Responder: answer a KEX_INIT. Writes SZLINK_SEC_KEX_RESP_LEN bytes. */
int szlink_sec_handle_kex_init(szlink_sec_t *s, const uint8_t in[SZLINK_SEC_KEX_INIT_LEN],
                               const uint8_t eph_priv[32], uint32_t now_ms,
                               uint8_t out[SZLINK_SEC_KEX_RESP_LEN]);

/** 1 if frames can be sealed now. */
int szlink_sec_has_session(const szlink_sec_t *s, uint32_t now_ms);

/**
 * Protect one frame in place. hdr is the 9-byte header (STX..MSGID); its
 * SEQ byte (hdr[3]) is overwritten with the low byte of the frame counter.
 * mode is SZLINK_SEC_ENCRYPTED or SZLINK_SEC_SIGNED; flags may add
 * SZLINK_SEC_FEC. Writes the SEC byte and the tag.
 * @return tag length, or < 0
 */
int szlink_sec_seal(szlink_sec_t *s, uint8_t hdr[SZLINK_SEC_HEADER_LEN], uint8_t *payload,
                    uint8_t len, uint8_t mode, uint8_t flags, uint32_t now_ms,
                    uint8_t *sec_out, uint8_t tag_out[SZLINK_SEC_TAG_MAX]);

/**
 * Verify one received frame and decrypt its payload in place. The payload
 * is only modified if the frame authenticates.
 * @return SZLINK_SEC_OK or < 0
 */
int szlink_sec_open(szlink_sec_t *s, const uint8_t hdr[SZLINK_SEC_HEADER_LEN], uint8_t *payload,
                    uint8_t len, uint8_t sec, const uint8_t *tag, uint8_t tag_len,
                    uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#ifdef SZLINK_SEC_IMPLEMENTATION

#include <string.h>
/* ArduPilot: -DSZLINK_SEC_MONOCYPHER_HEADER='<AP_CheckFirmware/monocypher.h>' */
#ifndef SZLINK_SEC_MONOCYPHER_HEADER
#define SZLINK_SEC_MONOCYPHER_HEADER "monocypher.h"
#endif
#include SZLINK_SEC_MONOCYPHER_HEADER

#ifdef __cplusplus
extern "C" {
#endif

static const char szlink_sec_protocol_name_[] = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
static const char szlink_sec_prologue_[] = "SZ-Link v1";

/* --- HMAC / HKDF with BLAKE2b ------------------------------------------- */

static void szlink_sec_hmac_(uint8_t out[64], const uint8_t *key, size_t key_len,
                             const uint8_t *d1, size_t l1, const uint8_t *d2, size_t l2)
{
    uint8_t k[128], pad[128], inner[64];
    crypto_blake2b_ctx ctx;
    size_t i;
    memset(k, 0, sizeof(k));
    if (key_len > sizeof(k)) {
        crypto_blake2b(k, key, key_len);
    } else {
        memcpy(k, key, key_len);
    }
    for (i = 0; i < 128u; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x36u);
    }
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, pad, sizeof(pad));
    crypto_blake2b_update(&ctx, d1, l1);
    crypto_blake2b_update(&ctx, d2, l2);
    crypto_blake2b_final(&ctx, inner);
    for (i = 0; i < 128u; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x5Cu);
    }
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, pad, sizeof(pad));
    crypto_blake2b_update(&ctx, inner, sizeof(inner));
    crypto_blake2b_final(&ctx, out);
    crypto_wipe(k, sizeof(k));
    crypto_wipe(pad, sizeof(pad));
    crypto_wipe(inner, sizeof(inner));
}

/* Noise HKDF with two outputs */
static void szlink_sec_hkdf2_(const uint8_t ck[64], const uint8_t *ikm, size_t ikm_len,
                              uint8_t out1[64], uint8_t out2[64])
{
    uint8_t temp[64];
    const uint8_t one = 1u, two = 2u;
    szlink_sec_hmac_(temp, ck, 64u, ikm, ikm_len, NULL, 0);
    szlink_sec_hmac_(out1, temp, 64u, &one, 1u, NULL, 0);
    szlink_sec_hmac_(out2, temp, 64u, out1, 64u, &two, 1u);
    crypto_wipe(temp, sizeof(temp));
}

/* HKDF-Expand(prk, label || extra, 32): a single HMAC block */
static void szlink_sec_expand32_(uint8_t out[32], const uint8_t prk[32], const char *label,
                                 const uint8_t *extra, size_t extra_len)
{
    uint8_t info[32];
    uint8_t full[64];
    size_t n = strlen(label);
    memcpy(info, label, n);
    if (extra_len) {
        memcpy(&info[n], extra, extra_len);
        n += extra_len;
    }
    info[n++] = 1u;
    szlink_sec_hmac_(full, prk, 32u, info, n, NULL, 0);
    memcpy(out, full, 32u);
    crypto_wipe(full, sizeof(full));
}

/* --- ChaCha20-Poly1305 (RFC 8439), AD in up to three pieces --------------- */

static const uint8_t szlink_sec_zero16_[16] = {0};

static void szlink_sec_tag_(uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *ad1, size_t l1, const uint8_t *ad2, size_t l2,
                            const uint8_t *ad3, size_t l3, const uint8_t *ct, size_t ct_len)
{
    uint8_t otk[64];
    uint8_t lens[16];
    crypto_poly1305_ctx ctx;
    uint64_t ad_len = (uint64_t)(l1 + l2 + l3);
    size_t i;
    memset(otk, 0, sizeof(otk));
    crypto_ietf_chacha20_ctr(otk, otk, sizeof(otk), key, nonce, 0);
    crypto_poly1305_init(&ctx, otk);
    crypto_poly1305_update(&ctx, ad1, l1);
    crypto_poly1305_update(&ctx, ad2, l2);
    crypto_poly1305_update(&ctx, ad3, l3);
    crypto_poly1305_update(&ctx, szlink_sec_zero16_, (size_t)((16u - (ad_len & 15u)) & 15u));
    crypto_poly1305_update(&ctx, ct, ct_len);
    crypto_poly1305_update(&ctx, szlink_sec_zero16_, (16u - (ct_len & 15u)) & 15u);
    for (i = 0; i < 8u; i++) {
        lens[i] = (uint8_t)(ad_len >> (8u * i));
        lens[8u + i] = (uint8_t)((uint64_t)ct_len >> (8u * i));
    }
    crypto_poly1305_update(&ctx, lens, sizeof(lens));
    crypto_poly1305_final(&ctx, tag);
    crypto_wipe(otk, sizeof(otk));
}

/* constant-time compare of n bytes */
static int szlink_sec_tag_eq_(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return d == 0;
}

/* --- X25519 --------------------------------------------------------------- */

static int szlink_sec_dh_(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32])
{
    uint8_t d = 0;
    size_t i;
    crypto_x25519(out, priv, pub);
    for (i = 0; i < 32u; i++) {
        d |= out[i];
    }
    return d != 0; /* reject low-order points */
}

void szlink_sec_keys_from_secret(const uint8_t secret[32], uint8_t vehicle_priv[32],
                                 uint8_t ground_priv[32])
{
    szlink_sec_expand32_(vehicle_priv, secret, "SZL vehicle key", NULL, 0);
    szlink_sec_expand32_(ground_priv, secret, "SZL ground key", NULL, 0);
}

void szlink_sec_public_key(uint8_t pub[32], const uint8_t priv[32])
{
    crypto_x25519_public_key(pub, priv);
}

/* --- Noise symmetric state ------------------------------------------------ */

static void szlink_sec_mix_hash_(szlink_sec_noise_t *n, const uint8_t *d, size_t len)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, n->h, 64u);
    crypto_blake2b_update(&ctx, d, len);
    crypto_blake2b_final(&ctx, n->h);
}

static void szlink_sec_mix_key_(szlink_sec_noise_t *n, const uint8_t ikm[32])
{
    uint8_t temp_k[64];
    szlink_sec_hkdf2_(n->ck, ikm, 32u, n->ck, temp_k);
    memcpy(n->k, temp_k, 32u);
    n->n = 0;
    crypto_wipe(temp_k, sizeof(temp_k));
}

static void szlink_sec_noise_nonce_(const szlink_sec_noise_t *n, uint8_t nonce[12])
{
    size_t i;
    memset(nonce, 0, 4u);
    for (i = 0; i < 8u; i++) {
        nonce[4u + i] = (uint8_t)(n->n >> (8u * i));
    }
}

/* out = ENCRYPT(p) || tag; len(out) = len + 16 */
static void szlink_sec_encrypt_and_hash_(szlink_sec_noise_t *n, const uint8_t *p, size_t len,
                                         uint8_t *out)
{
    uint8_t nonce[12];
    szlink_sec_noise_nonce_(n, nonce);
    crypto_ietf_chacha20_ctr(out, p, len, n->k, nonce, 1);
    szlink_sec_tag_(out + len, n->k, nonce, n->h, 64u, NULL, 0, NULL, 0, out, len);
    n->n++;
    szlink_sec_mix_hash_(n, out, len + 16u);
}

/* in has len + 16 bytes; writes len plaintext bytes */
static int szlink_sec_decrypt_and_hash_(szlink_sec_noise_t *n, const uint8_t *in, size_t len,
                                        uint8_t *p)
{
    uint8_t nonce[12], tag[16];
    szlink_sec_noise_nonce_(n, nonce);
    szlink_sec_tag_(tag, n->k, nonce, n->h, 64u, NULL, 0, NULL, 0, in, len);
    if (crypto_verify16(tag, in + len) != 0) {
        return 0;
    }
    crypto_ietf_chacha20_ctr(p, in, len, n->k, nonce, 1);
    n->n++;
    szlink_sec_mix_hash_(n, in, len + 16u);
    return 1;
}

static void szlink_sec_noise_start_(szlink_sec_noise_t *n, const uint8_t responder_static[32])
{
    memset(n, 0, sizeof(*n));
    memcpy(n->h, szlink_sec_protocol_name_, sizeof(szlink_sec_protocol_name_) - 1u);
    memcpy(n->ck, n->h, 64u);
    szlink_sec_mix_hash_(n, (const uint8_t *)szlink_sec_prologue_,
                         sizeof(szlink_sec_prologue_) - 1u);
    szlink_sec_mix_hash_(n, responder_static, 32u);
}

/* --- sessions ------------------------------------------------------------ */

static void szlink_sec_epoch_keys_(uint8_t keys[SZLINK_SEC_NUM_LCID][32], const uint8_t chain[32])
{
    uint8_t lcid;
    for (lcid = 0; lcid < SZLINK_SEC_NUM_LCID; lcid++) {
        szlink_sec_expand32_(keys[lcid], chain, "SZL lcid", &lcid, 1u);
    }
}

static void szlink_sec_next_chain_(uint8_t chain[32])
{
    uint8_t next[32];
    szlink_sec_expand32_(next, chain, "SZL chain", NULL, 0);
    memcpy(chain, next, 32u);
    crypto_wipe(next, sizeof(next));
}

static void szlink_sec_session_start_(szlink_sec_session_t *ss, const uint8_t k_i2r[32],
                                      const uint8_t k_r2i[32], uint8_t role, uint32_t now_ms)
{
    crypto_wipe(ss, sizeof(*ss));
    ss->valid = 1u;
    ss->start_ms = now_ms;
    memcpy(ss->tx_chain, role == SZLINK_SEC_INITIATOR ? k_i2r : k_r2i, 32u);
    memcpy(ss->rx_chain, role == SZLINK_SEC_INITIATOR ? k_r2i : k_i2r, 32u);
    szlink_sec_epoch_keys_(ss->tx_keys, ss->tx_chain);
    szlink_sec_epoch_keys_(ss->rx_cur.keys, ss->rx_chain);
}

static int szlink_sec_usable_(const szlink_sec_session_t *ss, uint32_t now_ms)
{
    return ss->valid && (uint32_t)(now_ms - ss->start_ms) < SZLINK_SEC_SESSION_MAX_MS;
}

static uint32_t szlink_sec_expected_epoch_(const szlink_sec_session_t *ss, uint32_t now_ms)
{
    return (uint32_t)(now_ms - ss->start_ms) / SZLINK_SEC_EPOCH_MS;
}

void szlink_sec_init(szlink_sec_t *s, uint8_t role, const uint8_t s_priv[32],
                     const uint8_t peer_pub[32])
{
    crypto_wipe(s, sizeof(*s));
    s->role = role;
    memcpy(s->s_priv, s_priv, 32u);
    memcpy(s->peer_pub, peer_pub, 32u);
    crypto_x25519_public_key(s->s_pub, s_priv);
    s->ss_ok = (uint8_t)szlink_sec_dh_(s->ss, s->s_priv, s->peer_pub);
}

void szlink_sec_wipe(szlink_sec_t *s)
{
    crypto_wipe(s, sizeof(*s));
}

uint8_t szlink_sec_tag_len(uint8_t lcid)
{
    return lcid == SZLINK_SEC_LCID_RC ? 8u : 16u;
}

static void szlink_sec_retire_current_(szlink_sec_t *s, uint32_t now_ms)
{
    if (s->cur.valid) {
        s->prev = s->cur;
        s->prev_until_ms = now_ms + SZLINK_SEC_PREV_GRACE_MS;
    }
    crypto_wipe(&s->cur, sizeof(s->cur));
}

int szlink_sec_needs_kex(const szlink_sec_t *s, uint32_t now_ms)
{
    uint32_t last;
    if (s->role != SZLINK_SEC_INITIATOR) {
        return 0;
    }
    if (s->hs_active && (uint32_t)(now_ms - s->hs_sent_ms) < SZLINK_SEC_KEX_RETRY_MS) {
        return 0;
    }
    if (!s->cur.valid || (uint32_t)(now_ms - s->cur.start_ms) >= SZLINK_SEC_REKEY_MS) {
        return 1;
    }
    /* nothing has authenticated for a while: the vehicle lost the session */
    last = s->cur.start_ms;
    if (s->have_rx && (int32_t)(s->last_rx_ms - last) > 0) {
        last = s->last_rx_ms;
    }
    return (uint32_t)(now_ms - last) >= SZLINK_SEC_RX_IDLE_REKEY_MS;
}

int szlink_sec_kex_init(szlink_sec_t *s, const uint8_t eph_priv[32], uint64_t timestamp_us,
                        uint32_t now_ms, uint8_t out[SZLINK_SEC_KEX_INIT_LEN])
{
    uint8_t dh[32], ts[8];
    size_t i;
    if (s->role != SZLINK_SEC_INITIATOR || !s->ss_ok) {
        return SZLINK_SEC_ERR_PARAM;
    }
    szlink_sec_noise_start_(&s->hs, s->peer_pub);
    memcpy(s->hs_e, eph_priv, 32u);
    crypto_x25519_public_key(out, s->hs_e);                       /* e */
    szlink_sec_mix_hash_(&s->hs, out, 32u);
    if (!szlink_sec_dh_(dh, s->hs_e, s->peer_pub)) {               /* es */
        return SZLINK_SEC_ERR_PARAM;
    }
    szlink_sec_mix_key_(&s->hs, dh);
    szlink_sec_encrypt_and_hash_(&s->hs, s->s_pub, 32u, out + 32); /* s */
    szlink_sec_mix_key_(&s->hs, s->ss);                            /* ss */
    for (i = 0; i < 8u; i++) {
        ts[i] = (uint8_t)(timestamp_us >> (8u * i));
    }
    szlink_sec_encrypt_and_hash_(&s->hs, ts, 8u, out + 80);       /* payload */
    crypto_wipe(dh, sizeof(dh));
    s->hs_active = 1u;
    s->hs_sent_ms = now_ms;
    return SZLINK_SEC_OK;
}

int szlink_sec_handle_kex_resp(szlink_sec_t *s, const uint8_t in[SZLINK_SEC_KEX_RESP_LEN],
                               uint32_t now_ms)
{
    szlink_sec_noise_t n;
    uint8_t dh[32], k1[64], k2[64];
    int ok;
    if (s->role != SZLINK_SEC_INITIATOR || !s->hs_active) {
        return SZLINK_SEC_ERR_PARAM;
    }
    n = s->hs; /* only commit if the response authenticates */
    szlink_sec_mix_hash_(&n, in, 32u);
    ok = szlink_sec_dh_(dh, s->hs_e, in);                          /* ee */
    szlink_sec_mix_key_(&n, dh);
    ok &= szlink_sec_dh_(dh, s->s_priv, in);                       /* se */
    szlink_sec_mix_key_(&n, dh);
    ok = ok && szlink_sec_decrypt_and_hash_(&n, in + 32, 0, NULL);
    if (!ok) {
        crypto_wipe(&n, sizeof(n));
        crypto_wipe(dh, sizeof(dh));
        s->stats.auth_fail++;
        return SZLINK_SEC_ERR_AUTH;
    }
    szlink_sec_hkdf2_(n.ck, NULL, 0, k1, k2);
    szlink_sec_retire_current_(s, now_ms);
    szlink_sec_session_start_(&s->cur, k1, k2, SZLINK_SEC_INITIATOR, now_ms);
    s->stats.rekeys++;
    s->hs_active = 0;
    crypto_wipe(&s->hs, sizeof(s->hs));
    crypto_wipe(s->hs_e, sizeof(s->hs_e));
    crypto_wipe(&n, sizeof(n));
    crypto_wipe(dh, sizeof(dh));
    crypto_wipe(k1, sizeof(k1));
    crypto_wipe(k2, sizeof(k2));
    return SZLINK_SEC_OK;
}

int szlink_sec_handle_kex_init(szlink_sec_t *s, const uint8_t in[SZLINK_SEC_KEX_INIT_LEN],
                               const uint8_t eph_priv[32], uint32_t now_ms,
                               uint8_t out[SZLINK_SEC_KEX_RESP_LEN])
{
    szlink_sec_noise_t n;
    uint8_t dh[32], rs[32], ts_bytes[8], k1[64], k2[64];
    uint64_t ts = 0;
    int ok, i;
    if (s->role != SZLINK_SEC_RESPONDER || !s->ss_ok) {
        return SZLINK_SEC_ERR_PARAM;
    }
    szlink_sec_noise_start_(&n, s->s_pub);
    szlink_sec_mix_hash_(&n, in, 32u);                              /* e */
    ok = szlink_sec_dh_(dh, s->s_priv, in);                         /* es */
    szlink_sec_mix_key_(&n, dh);
    ok = ok && szlink_sec_decrypt_and_hash_(&n, in + 32, 32u, rs);  /* s */
    ok = ok && crypto_verify32(rs, s->peer_pub) == 0;
    if (ok) {
        szlink_sec_mix_key_(&n, s->ss);                             /* ss */
        ok = szlink_sec_decrypt_and_hash_(&n, in + 80, 8u, ts_bytes);
    }
    if (!ok) {
        s->stats.kex_rejected++;
        crypto_wipe(&n, sizeof(n));
        crypto_wipe(dh, sizeof(dh));
        return SZLINK_SEC_ERR_AUTH;
    }
    for (i = 7; i >= 0; i--) {
        ts = (ts << 8) | ts_bytes[i];
    }
    if (s->have_kex_ts && ts <= s->last_kex_ts) {
        s->stats.kex_replay++;
        crypto_wipe(&n, sizeof(n));
        crypto_wipe(dh, sizeof(dh));
        return SZLINK_SEC_ERR_REPLAY;
    }
    crypto_x25519_public_key(out, eph_priv);                        /* e */
    szlink_sec_mix_hash_(&n, out, 32u);
    ok = szlink_sec_dh_(dh, eph_priv, in);                          /* ee */
    szlink_sec_mix_key_(&n, dh);
    ok &= szlink_sec_dh_(dh, eph_priv, s->peer_pub);                /* se */
    szlink_sec_mix_key_(&n, dh);
    szlink_sec_encrypt_and_hash_(&n, NULL, 0, out + 32);
    if (ok) {
        szlink_sec_hkdf2_(n.ck, NULL, 0, k1, k2);
        szlink_sec_session_start_(&s->pending, k1, k2, SZLINK_SEC_RESPONDER, now_ms);
        s->last_kex_ts = ts;
        s->have_kex_ts = 1u;
    }
    crypto_wipe(&n, sizeof(n));
    crypto_wipe(dh, sizeof(dh));
    crypto_wipe(k1, sizeof(k1));
    crypto_wipe(k2, sizeof(k2));
    return ok ? SZLINK_SEC_OK : SZLINK_SEC_ERR_AUTH;
}

static szlink_sec_session_t *szlink_sec_tx_session_(szlink_sec_t *s, uint32_t now_ms)
{
    if (szlink_sec_usable_(&s->cur, now_ms)) {
        return &s->cur;
    }
    if (szlink_sec_usable_(&s->pending, now_ms)) {
        return &s->pending;
    }
    return NULL;
}

int szlink_sec_has_session(const szlink_sec_t *s, uint32_t now_ms)
{
    return szlink_sec_usable_(&s->cur, now_ms) || szlink_sec_usable_(&s->pending, now_ms);
}

static void szlink_sec_nonce_(uint8_t nonce[12], uint32_t epoch, uint8_t lcid, uint32_t ctr)
{
    size_t i;
    memset(nonce, 0, 12u);
    for (i = 0; i < 4u; i++) {
        nonce[i] = (uint8_t)(epoch >> (8u * i));
        nonce[8u + i] = (uint8_t)(ctr >> (8u * i));
    }
    nonce[4] = lcid;
}

int szlink_sec_seal(szlink_sec_t *s, uint8_t hdr[SZLINK_SEC_HEADER_LEN], uint8_t *payload,
                    uint8_t len, uint8_t mode, uint8_t flags, uint32_t now_ms,
                    uint8_t *sec_out, uint8_t tag_out[SZLINK_SEC_TAG_MAX])
{
    szlink_sec_session_t *ss;
    uint8_t lcid = hdr[2], sec, nonce[12], tag[16];
    uint32_t epoch, ctr;
    if ((mode != SZLINK_SEC_ENCRYPTED && mode != SZLINK_SEC_SIGNED) ||
        lcid >= SZLINK_SEC_NUM_LCID) {
        return SZLINK_SEC_ERR_PARAM;
    }
    ss = szlink_sec_tx_session_(s, now_ms);
    if (ss == NULL) {
        return SZLINK_SEC_ERR_NO_SESSION;
    }
    epoch = szlink_sec_expected_epoch_(ss, now_ms);
    if (epoch > ss->tx_epoch) {
        while (ss->tx_epoch < epoch) {
            szlink_sec_next_chain_(ss->tx_chain);
            ss->tx_epoch++;
        }
        szlink_sec_epoch_keys_(ss->tx_keys, ss->tx_chain);
        memset(ss->tx_ctr, 0, sizeof(ss->tx_ctr));
        memset(ss->tx_ctr_exhausted, 0, sizeof(ss->tx_ctr_exhausted));
    }
    if (ss->tx_ctr_exhausted[lcid]) {
        return SZLINK_SEC_ERR_NO_SESSION;
    }
    ctr = ss->tx_ctr[lcid]++;
    if (ss->tx_ctr[lcid] == 0) {
        ss->tx_ctr_exhausted[lcid] = 1u;
    }
    hdr[3] = (uint8_t)(ctr & 0xFFu);
    sec = (uint8_t)(mode | (flags & SZLINK_SEC_FEC) |
                    ((ss->tx_epoch & 3u) << SZLINK_SEC_EPOCH_SHIFT));
    szlink_sec_nonce_(nonce, ss->tx_epoch, lcid, ctr);
    if (mode == SZLINK_SEC_ENCRYPTED) {
        crypto_ietf_chacha20_ctr(payload, payload, len, ss->tx_keys[lcid], nonce, 1);
        szlink_sec_tag_(tag, ss->tx_keys[lcid], nonce, hdr, SZLINK_SEC_HEADER_LEN, &sec, 1u,
                        NULL, 0, payload, len);
    } else {
        szlink_sec_tag_(tag, ss->tx_keys[lcid], nonce, hdr, SZLINK_SEC_HEADER_LEN, &sec, 1u,
                        payload, len, NULL, 0);
    }
    *sec_out = sec;
    memcpy(tag_out, tag, szlink_sec_tag_len(lcid));
    return szlink_sec_tag_len(lcid);
}

/* --- receive ------------------------------------------------------------- */

static int szlink_sec_fresh_(const szlink_sec_replay_t *w, uint32_t c)
{
    uint32_t off;
    if (!w->has_top || c > w->top) {
        return 1;
    }
    off = w->top - c;
    return off < SZLINK_SEC_REPLAY_WINDOW && !((w->bits >> off) & 1u);
}

static void szlink_sec_accept_(szlink_sec_replay_t *w, uint32_t c)
{
    if (!w->has_top) {
        w->has_top = 1u;
        w->top = c;
        w->bits = 1u;
    } else if (c > w->top) {
        uint32_t shift = c - w->top;
        w->bits = shift >= 64u ? 1u : ((w->bits << shift) | 1u);
        w->top = c;
    } else {
        w->bits |= (uint64_t)1u << (w->top - c);
    }
}

/* try every plausible counter for seq; on success payload is decrypted */
static int szlink_sec_open_in_(szlink_sec_epoch_t *ep, const uint8_t *hdr, uint8_t *payload,
                               uint8_t len, uint8_t sec, const uint8_t *tag, uint8_t tag_len)
{
    uint8_t lcid = hdr[2], seq = hdr[3];
    szlink_sec_replay_t *w = &ep->win[lcid];
    const uint8_t *key = ep->keys[lcid];
    int64_t base = w->has_top ? (int64_t)w->top + 1 : 0;
    int64_t c = (base & ~(int64_t)0xFF) | seq;
    uint32_t k;
    if (c < base - 128) {
        c += 256;
    } else if (c > base + 127 && c >= 256) {
        c -= 256;
    }
    for (k = 0; k <= SZLINK_SEC_COUNTER_SEARCH; k++, c += 256) {
        uint8_t nonce[12], expect[16];
        if (c > (int64_t)0xFFFFFFFF) {
            break;
        }
        if (!szlink_sec_fresh_(w, (uint32_t)c)) {
            continue;
        }
        szlink_sec_nonce_(nonce, ep->epoch, lcid, (uint32_t)c);
        if (sec & SZLINK_SEC_ENCRYPTED) {
            szlink_sec_tag_(expect, key, nonce, hdr, SZLINK_SEC_HEADER_LEN, &sec, 1u,
                            NULL, 0, payload, len);
        } else {
            szlink_sec_tag_(expect, key, nonce, hdr, SZLINK_SEC_HEADER_LEN, &sec, 1u,
                            payload, len, NULL, 0);
        }
        if (!szlink_sec_tag_eq_(expect, tag, tag_len)) {
            continue;
        }
        if (sec & SZLINK_SEC_ENCRYPTED) {
            crypto_ietf_chacha20_ctr(payload, payload, len, key, nonce, 1);
        }
        szlink_sec_accept_(w, (uint32_t)c);
        return 1;
    }
    return 0;
}

static int szlink_sec_rx_open_(szlink_sec_session_t *ss, const uint8_t *hdr, uint8_t *payload,
                               uint8_t len, uint8_t sec, const uint8_t *tag, uint8_t tag_len,
                               uint32_t epoch)
{
    szlink_sec_epoch_t cand, before;
    uint8_t chain[32];
    uint32_t e;
    int have_before = 0, ok;
    if (epoch == ss->rx_cur.epoch) {
        return szlink_sec_open_in_(&ss->rx_cur, hdr, payload, len, sec, tag, tag_len);
    }
    if (ss->rx_has_prev && epoch == ss->rx_prev.epoch) {
        return szlink_sec_open_in_(&ss->rx_prev, hdr, payload, len, sec, tag, tag_len);
    }
    if (epoch < ss->rx_cur.epoch) {
        return 0;
    }
    /* ratchet forward on a copy, commit only if the frame authenticates */
    memcpy(chain, ss->rx_chain, 32u);
    for (e = ss->rx_cur.epoch; e < epoch; e++) {
        if (e == epoch - 1u && e != ss->rx_cur.epoch) {
            memset(&before, 0, sizeof(before));
            before.epoch = e;
            szlink_sec_epoch_keys_(before.keys, chain);
            have_before = 1;
        }
        szlink_sec_next_chain_(chain);
    }
    memset(&cand, 0, sizeof(cand));
    cand.epoch = epoch;
    szlink_sec_epoch_keys_(cand.keys, chain);
    ok = szlink_sec_open_in_(&cand, hdr, payload, len, sec, tag, tag_len);
    if (ok) {
        if (have_before) {
            ss->rx_prev = before;
        } else {
            ss->rx_prev = ss->rx_cur; /* advanced by exactly one epoch */
        }
        ss->rx_has_prev = 1u;
        ss->rx_cur = cand;
        memcpy(ss->rx_chain, chain, 32u);
    }
    crypto_wipe(&cand, sizeof(cand));
    crypto_wipe(&before, sizeof(before));
    crypto_wipe(chain, sizeof(chain));
    return ok;
}

/* map the 2-bit epoch onto the epoch nearest to the receiver's estimate */
static int szlink_sec_resolve_epoch_(uint8_t bits, uint32_t expected, uint32_t *epoch)
{
    uint32_t d = (uint32_t)(bits - expected) & 3u;
    if (d == 2u) {
        return 0;
    }
    if (d == 3u) {
        if (expected == 0u) {
            return 0;
        }
        *epoch = expected - 1u;
    } else {
        *epoch = expected + d;
    }
    return 1;
}

int szlink_sec_open(szlink_sec_t *s, const uint8_t hdr[SZLINK_SEC_HEADER_LEN], uint8_t *payload,
                    uint8_t len, uint8_t sec, const uint8_t *tag, uint8_t tag_len,
                    uint32_t now_ms)
{
    szlink_sec_session_t *order[3];
    uint8_t bits = (uint8_t)((sec & SZLINK_SEC_EPOCH_MASK) >> SZLINK_SEC_EPOCH_SHIFT);
    int i;
    if (!(sec & SZLINK_SEC_PROTECTED) || hdr[2] >= SZLINK_SEC_NUM_LCID ||
        tag_len != szlink_sec_tag_len(hdr[2])) {
        return SZLINK_SEC_ERR_PARAM;
    }
    order[0] = &s->cur;
    order[1] = &s->pending;
    order[2] = (int32_t)(now_ms - s->prev_until_ms) < 0 ? &s->prev : NULL;
    for (i = 0; i < 3; i++) {
        szlink_sec_session_t *ss = order[i];
        uint32_t epoch;
        if (ss == NULL || !szlink_sec_usable_(ss, now_ms)) {
            continue;
        }
        if (!szlink_sec_resolve_epoch_(bits, szlink_sec_expected_epoch_(ss, now_ms), &epoch)) {
            continue;
        }
        if (!szlink_sec_rx_open_(ss, hdr, payload, len, sec, tag, tag_len, epoch)) {
            continue;
        }
        s->last_rx_ms = now_ms;
        s->have_rx = 1u;
        if (ss == &s->pending) {
            /* the initiator proved it has the new keys */
            szlink_sec_retire_current_(s, now_ms);
            s->cur = s->pending;
            crypto_wipe(&s->pending, sizeof(s->pending));
            s->stats.rekeys++;
        }
        return SZLINK_SEC_OK;
    }
    s->stats.auth_fail++;
    return SZLINK_SEC_ERR_AUTH;
}

#ifdef __cplusplus
}
#endif

#endif /* SZLINK_SEC_IMPLEMENTATION */
#endif /* SZLINK_SEC_H */
