/**
 * @file szfw.h
 * @brief SpaceZet ESC firmware update: signed images and the ESC side of
 *        the spacezet.fw.BootCommand / FirmwareChunk DroneCAN services.
 *
 * Image = 80-byte header || body.
 *
 *   offset size
 *   0      4    magic "SZFW"
 *   4      1    format (1)
 *   5      1    key_id: index into the ESC's list of trusted public keys
 *   6      2    board_id (u16 LE): ESC hardware type
 *   8      4    fw_version (u32 LE)
 *   12     4    body_size (u32 LE)
 *   16     64   signature: EdDSA (Ed25519 + BLAKE2b, Monocypher crypto_sign,
 *               the key type of ArduPilot signed firmware) over
 *               header[0..15] || body
 *
 * The ESC (bootloader or application with a staging area) feeds the
 * service requests to szfw_boot_command() / szfw_chunk(); the body is
 * written to staging flash through callbacks and its signature is checked
 * by reading the flash back at COMMIT, before install() is called. Nothing
 * unsigned or signed by an unknown key is ever installed.
 *
 * Depends on Monocypher 3.1.x (crypto_check_*). No allocation, no clock.
 * In exactly one translation unit:
 *     #define SZFW_IMPLEMENTATION
 *     #include "szfw.h"
 */
#ifndef SZFW_H
#define SZFW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SZFW_HEADER_LEN 80u
#define SZFW_SIGNED_HEADER_LEN 16u
#define SZFW_FORMAT 1u
#define SZFW_CHUNK_MAX 192u

/* spacezet.fw.BootCommand.command */
enum {
    SZFW_COMMAND_BEGIN = 0,
    SZFW_COMMAND_COMMIT = 1,
    SZFW_COMMAND_ABORT = 2,
    SZFW_COMMAND_STATUS = 3
};

/* spacezet.fw.BootCommand.status (also used by FirmwareChunk) */
enum {
    SZFW_STATUS_OK = 0,
    SZFW_STATUS_BUSY = 1,
    SZFW_STATUS_BAD_HEADER = 2,
    SZFW_STATUS_WRONG_BOARD = 3,
    SZFW_STATUS_UNKNOWN_KEY = 4,
    SZFW_STATUS_TOO_LARGE = 5,
    SZFW_STATUS_DOWNGRADE = 6,
    SZFW_STATUS_NOT_STARTED = 7,
    SZFW_STATUS_BAD_OFFSET = 8,
    SZFW_STATUS_INCOMPLETE = 9,
    SZFW_STATUS_BAD_SIGNATURE = 10,
    SZFW_STATUS_FLASH_ERROR = 11
};

typedef struct {
    uint8_t format;
    uint8_t key_id;
    uint16_t board_id;
    uint32_t fw_version;
    uint32_t body_size;
} szfw_header_t;

/** Staging flash access; each returns 0 on success. */
typedef struct {
    void *ctx;
    /* prepare the staging area for size bytes (erase) */
    int (*erase)(void *ctx, uint32_t size);
    int (*write)(void *ctx, uint32_t offset, const uint8_t *data, uint32_t len);
    int (*read)(void *ctx, uint32_t offset, uint8_t *data, uint32_t len);
    /* the staged body is verified: install it (copy to the application
     * slot, record the version, reboot). May not return. */
    int (*install)(void *ctx, const szfw_header_t *hdr);
} szfw_flash_t;

typedef struct {
    /* configuration, set before use */
    const uint8_t (*keys)[32];  /* trusted public keys, indexed by key_id */
    uint8_t num_keys;
    uint16_t board_id;
    uint32_t max_body_size;     /* staging area size */
    uint32_t installed_version; /* images older than this are refused */
    szfw_flash_t flash;

    /* state */
    uint8_t active;
    uint8_t header[SZFW_HEADER_LEN];
    szfw_header_t hdr;
    uint32_t next_offset;
} szfw_updater_t;

/** Parse a header; returns SZFW_STATUS_OK or BAD_HEADER. */
uint8_t szfw_parse_header(const uint8_t *buf, size_t len, szfw_header_t *hdr);

/** Check a whole image in memory against a key list (for tools and the FC). */
uint8_t szfw_verify_image(const uint8_t *image, size_t len, const uint8_t (*keys)[32],
                          uint8_t num_keys);

/** Reset the update state (keeps the configuration). */
void szfw_updater_reset(szfw_updater_t *u);

/**
 * Handle a BootCommand request. busy: the motor is armed or running
 * (BEGIN and COMMIT are refused). Fills next_offset/body_size for the
 * response and returns its status.
 */
uint8_t szfw_boot_command(szfw_updater_t *u, uint8_t command, const uint8_t *header,
                          size_t header_len, int busy, uint32_t *next_offset, uint32_t *body_size);

/** Handle a FirmwareChunk request. */
uint8_t szfw_chunk(szfw_updater_t *u, uint32_t offset, const uint8_t *data, size_t len,
                   uint32_t *next_offset);

#ifdef __cplusplus
}
#endif

#endif /* SZFW_H */

/* ======================================================================== */
#ifdef SZFW_IMPLEMENTATION
#ifndef SZFW_IMPLEMENTATION_DONE
#define SZFW_IMPLEMENTATION_DONE

#include <string.h>
#ifdef SZFW_MONOCYPHER_HEADER
#include SZFW_MONOCYPHER_HEADER
#else
#include "monocypher.h"
#endif

static uint32_t szfw_le32_(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint8_t szfw_parse_header(const uint8_t *buf, size_t len, szfw_header_t *hdr)
{
    if (len != SZFW_HEADER_LEN || memcmp(buf, "SZFW", 4) != 0 || buf[4] != SZFW_FORMAT) {
        return SZFW_STATUS_BAD_HEADER;
    }
    hdr->format = buf[4];
    hdr->key_id = buf[5];
    hdr->board_id = (uint16_t)(buf[6] | (buf[7] << 8));
    hdr->fw_version = szfw_le32_(&buf[8]);
    hdr->body_size = szfw_le32_(&buf[12]);
    return SZFW_STATUS_OK;
}

static uint8_t szfw_check_key_(const szfw_header_t *hdr, const uint8_t (*keys)[32], uint8_t num_keys)
{
    size_t i;
    uint8_t any = 0;
    if (keys == NULL || hdr->key_id >= num_keys) {
        return SZFW_STATUS_UNKNOWN_KEY;
    }
    for (i = 0; i < 32u; i++) {
        any |= keys[hdr->key_id][i];
    }
    return any ? SZFW_STATUS_OK : SZFW_STATUS_UNKNOWN_KEY; /* empty key slot */
}

uint8_t szfw_verify_image(const uint8_t *image, size_t len, const uint8_t (*keys)[32],
                          uint8_t num_keys)
{
    szfw_header_t hdr;
    crypto_check_ctx ctx;
    crypto_check_ctx_abstract *actx = (crypto_check_ctx_abstract *)&ctx;
    uint8_t st;
    if (len < SZFW_HEADER_LEN) {
        return SZFW_STATUS_BAD_HEADER;
    }
    st = szfw_parse_header(image, SZFW_HEADER_LEN, &hdr);
    if (st != SZFW_STATUS_OK) {
        return st;
    }
    if (hdr.body_size != len - SZFW_HEADER_LEN) {
        return SZFW_STATUS_INCOMPLETE;
    }
    st = szfw_check_key_(&hdr, keys, num_keys);
    if (st != SZFW_STATUS_OK) {
        return st;
    }
    crypto_check_init(actx, &image[16], keys[hdr.key_id]);
    crypto_check_update(actx, image, SZFW_SIGNED_HEADER_LEN);
    crypto_check_update(actx, &image[SZFW_HEADER_LEN], hdr.body_size);
    return crypto_check_final(actx) == 0 ? SZFW_STATUS_OK : SZFW_STATUS_BAD_SIGNATURE;
}

void szfw_updater_reset(szfw_updater_t *u)
{
    u->active = 0;
    u->next_offset = 0;
    memset(u->header, 0, sizeof(u->header));
    memset(&u->hdr, 0, sizeof(u->hdr));
}

/* verify the staged body by reading it back from flash */
static uint8_t szfw_verify_staged_(szfw_updater_t *u)
{
    crypto_check_ctx ctx;
    crypto_check_ctx_abstract *actx = (crypto_check_ctx_abstract *)&ctx;
    uint8_t buf[256];
    uint32_t off = 0;
    crypto_check_init(actx, &u->header[16], u->keys[u->hdr.key_id]);
    crypto_check_update(actx, u->header, SZFW_SIGNED_HEADER_LEN);
    while (off < u->hdr.body_size) {
        uint32_t n = u->hdr.body_size - off;
        if (n > sizeof(buf)) {
            n = sizeof(buf);
        }
        if (u->flash.read(u->flash.ctx, off, buf, n) != 0) {
            return SZFW_STATUS_FLASH_ERROR;
        }
        crypto_check_update(actx, buf, n);
        off += n;
    }
    return crypto_check_final(actx) == 0 ? SZFW_STATUS_OK : SZFW_STATUS_BAD_SIGNATURE;
}

uint8_t szfw_boot_command(szfw_updater_t *u, uint8_t command, const uint8_t *header,
                          size_t header_len, int busy, uint32_t *next_offset, uint32_t *body_size)
{
    uint8_t st = SZFW_STATUS_OK;
    szfw_header_t hdr;

    switch (command) {
    case SZFW_COMMAND_BEGIN:
        if (busy) {
            st = SZFW_STATUS_BUSY;
            break;
        }
        szfw_updater_reset(u);
        st = szfw_parse_header(header, header_len, &hdr);
        if (st != SZFW_STATUS_OK) {
            break;
        }
        if (hdr.board_id != u->board_id) {
            st = SZFW_STATUS_WRONG_BOARD;
        } else if ((st = szfw_check_key_(&hdr, u->keys, u->num_keys)) != SZFW_STATUS_OK) {
            /* st set */
        } else if (hdr.body_size == 0u || hdr.body_size > u->max_body_size) {
            st = SZFW_STATUS_TOO_LARGE;
        } else if (hdr.fw_version < u->installed_version) {
            st = SZFW_STATUS_DOWNGRADE;
        } else if (u->flash.erase(u->flash.ctx, hdr.body_size) != 0) {
            st = SZFW_STATUS_FLASH_ERROR;
        } else {
            memcpy(u->header, header, SZFW_HEADER_LEN);
            u->hdr = hdr;
            u->active = 1u;
        }
        break;

    case SZFW_COMMAND_COMMIT:
        if (!u->active) {
            st = SZFW_STATUS_NOT_STARTED;
        } else if (busy) {
            st = SZFW_STATUS_BUSY;
        } else if (u->next_offset != u->hdr.body_size) {
            st = SZFW_STATUS_INCOMPLETE;
        } else {
            st = szfw_verify_staged_(u);
            if (st == SZFW_STATUS_OK) {
                const szfw_header_t installed = u->hdr;
                if (u->flash.install(u->flash.ctx, &installed) != 0) {
                    st = SZFW_STATUS_FLASH_ERROR;
                } else {
                    u->installed_version = installed.fw_version;
                }
            }
            /* done, or a bad image that more chunks cannot fix: start again */
            szfw_updater_reset(u);
        }
        break;

    case SZFW_COMMAND_ABORT:
        szfw_updater_reset(u);
        break;

    case SZFW_COMMAND_STATUS:
        st = u->active ? SZFW_STATUS_OK : SZFW_STATUS_NOT_STARTED;
        break;

    default:
        st = SZFW_STATUS_BAD_HEADER;
        break;
    }
    *next_offset = u->next_offset;
    *body_size = u->active ? u->hdr.body_size : 0u;
    return st;
}

uint8_t szfw_chunk(szfw_updater_t *u, uint32_t offset, const uint8_t *data, size_t len,
                   uint32_t *next_offset)
{
    uint8_t st = SZFW_STATUS_OK;
    if (!u->active) {
        st = SZFW_STATUS_NOT_STARTED;
    } else if (len > SZFW_CHUNK_MAX) {
        st = SZFW_STATUS_BAD_OFFSET;
    } else if (len > 0u && offset < u->next_offset && offset + len == u->next_offset) {
        /* the response was lost and the chunk repeated: acknowledge again */
    } else if (offset != u->next_offset || len == 0u ||
               len > u->hdr.body_size - u->next_offset) {
        st = SZFW_STATUS_BAD_OFFSET;
    } else if (u->flash.write(u->flash.ctx, offset, data, (uint32_t)len) != 0) {
        st = SZFW_STATUS_FLASH_ERROR;
    } else {
        u->next_offset += (uint32_t)len;
    }
    *next_offset = u->next_offset;
    return st;
}

#endif /* SZFW_IMPLEMENTATION_DONE */
#endif /* SZFW_IMPLEMENTATION */
