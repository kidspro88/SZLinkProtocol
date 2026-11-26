/* Tests for szfw.h: images signed by the Python tool, and the ESC update
 * state machine on a RAM "flash". */
#define SZFW_IMPLEMENTATION
#include "szfw.h"
#include "szfw_test_vectors.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);               \
            failures++;                                                       \
        }                                                                     \
    } while (0)

#define BODY_OFF SZFW_HEADER_LEN
#define BODY_LEN (sizeof(tv_image) - SZFW_HEADER_LEN)

typedef struct {
    uint8_t mem[4096];
    uint32_t erased;
    int erases;
    int installs;
    uint32_t installed_version;
    int fail_write;
} ram_flash_t;

static int rf_erase(void *ctx, uint32_t size)
{
    ram_flash_t *f = (ram_flash_t *)ctx;
    memset(f->mem, 0xFF, size);
    f->erased = size;
    f->erases++;
    return 0;
}

static int rf_write(void *ctx, uint32_t off, const uint8_t *d, uint32_t n)
{
    ram_flash_t *f = (ram_flash_t *)ctx;
    if (f->fail_write || off + n > f->erased) {
        return -1;
    }
    memcpy(&f->mem[off], d, n);
    return 0;
}

static int rf_read(void *ctx, uint32_t off, uint8_t *d, uint32_t n)
{
    ram_flash_t *f = (ram_flash_t *)ctx;
    memcpy(d, &f->mem[off], n);
    return 0;
}

static int rf_install(void *ctx, const szfw_header_t *h)
{
    ram_flash_t *f = (ram_flash_t *)ctx;
    f->installs++;
    f->installed_version = h->fw_version;
    return 0;
}

/* key 0 is an empty slot, key 1 is the signing key */
static uint8_t keys[2][32];

static void setup(szfw_updater_t *u, ram_flash_t *f)
{
    memset(f, 0, sizeof(*f));
    memset(u, 0, sizeof(*u));
    memcpy(keys[1], tv_key, 32);
    u->keys = (const uint8_t (*)[32])keys;
    u->num_keys = 2;
    u->board_id = 7;
    u->max_body_size = sizeof(f->mem);
    u->installed_version = 0x00010000;
    u->flash.ctx = f;
    u->flash.erase = rf_erase;
    u->flash.write = rf_write;
    u->flash.read = rf_read;
    u->flash.install = rf_install;
}

static uint8_t send_body(szfw_updater_t *u, const uint8_t *body, uint32_t len)
{
    uint32_t off = 0, next = 0;
    while (off < len) {
        uint32_t n = len - off > SZFW_CHUNK_MAX ? SZFW_CHUNK_MAX : len - off;
        uint8_t st = szfw_chunk(u, off, &body[off], n, &next);
        if (st != SZFW_STATUS_OK) {
            return st;
        }
        off = next;
    }
    return SZFW_STATUS_OK;
}

static void test_verify_image(void)
{
    uint8_t img[sizeof(tv_image)];
    const uint8_t (*k)[32] = (const uint8_t (*)[32])keys;
    szfw_header_t h;
    memcpy(keys[1], tv_key, 32);
    CHECK(szfw_parse_header(tv_image, SZFW_HEADER_LEN, &h) == SZFW_STATUS_OK);
    CHECK(h.key_id == 1 && h.board_id == 7 && h.fw_version == 0x00010200 && h.body_size == BODY_LEN);
    CHECK(szfw_verify_image(tv_image, sizeof(tv_image), k, 2) == SZFW_STATUS_OK);
    memcpy(img, tv_image, sizeof(img));
    img[BODY_OFF + 500] ^= 1;
    CHECK(szfw_verify_image(img, sizeof(img), k, 2) == SZFW_STATUS_BAD_SIGNATURE);
    memcpy(img, tv_image, sizeof(img));
    img[8] ^= 1; /* version is signed too */
    CHECK(szfw_verify_image(img, sizeof(img), k, 2) == SZFW_STATUS_BAD_SIGNATURE);
    CHECK(szfw_verify_image(tv_image, sizeof(tv_image) - 1, k, 2) == SZFW_STATUS_INCOMPLETE);
    CHECK(szfw_verify_image(tv_image, sizeof(tv_image), k, 1) == SZFW_STATUS_UNKNOWN_KEY);
    memcpy(keys[1], tv_other_key, 32);
    CHECK(szfw_verify_image(tv_image, sizeof(tv_image), k, 2) == SZFW_STATUS_BAD_SIGNATURE);
}

static void test_update_ok(void)
{
    szfw_updater_t u;
    ram_flash_t f;
    uint32_t next, size;
    setup(&u, &f);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_STATUS, NULL, 0, 0, &next, &size) == SZFW_STATUS_NOT_STARTED);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_OK);
    CHECK(next == 0 && size == BODY_LEN);
    /* a repeated BEGIN (first response lost) does not erase again */
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_OK);
    CHECK(next == 0 && size == BODY_LEN && f.erases == 1);
    /* first chunk, repeated chunk (lost response), wrong offset */
    CHECK(szfw_chunk(&u, 0, &tv_image[BODY_OFF], 192, &next) == SZFW_STATUS_OK && next == 192);
    CHECK(szfw_chunk(&u, 0, &tv_image[BODY_OFF], 192, &next) == SZFW_STATUS_OK && next == 192);
    CHECK(szfw_chunk(&u, 500, &tv_image[BODY_OFF], 10, &next) == SZFW_STATUS_BAD_OFFSET && next == 192);
    CHECK(szfw_chunk(&u, 192, &tv_image[BODY_OFF], 193, &next) == SZFW_STATUS_BAD_OFFSET);
    /* commit before the end */
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_COMMIT, NULL, 0, 0, &next, &size) == SZFW_STATUS_INCOMPLETE);
    /* COMMIT reset the state: start again and finish */
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_OK);
    CHECK(send_body(&u, &tv_image[BODY_OFF], BODY_LEN) == SZFW_STATUS_OK);
    /* no writing past the declared size */
    CHECK(szfw_chunk(&u, BODY_LEN, &tv_image[BODY_OFF], 1, &next) == SZFW_STATUS_BAD_OFFSET);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_COMMIT, NULL, 0, 1, &next, &size) == SZFW_STATUS_BUSY);
    CHECK(f.installs == 0);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_COMMIT, NULL, 0, 0, &next, &size) == SZFW_STATUS_OK);
    CHECK(f.installs == 1 && f.installed_version == 0x00010200);
    CHECK(u.installed_version == 0x00010200);
    /* a repeated COMMIT (first response lost) answers OK and installs nothing more */
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_COMMIT, NULL, 0, 0, &next, &size) == SZFW_STATUS_OK);
    CHECK(f.installs == 1 && size == 0);
    /* the same image again is fine, an older one is not (see test_rejections) */
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_OK);
}

static void test_rejections(void)
{
    szfw_updater_t u;
    ram_flash_t f;
    uint32_t next, size;
    uint8_t hdr[SZFW_HEADER_LEN];
    uint8_t body[BODY_LEN];

    setup(&u, &f);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 1, &next, &size) ==
          SZFW_STATUS_BUSY);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, 79, 0, &next, &size) == SZFW_STATUS_BAD_HEADER);
    CHECK(szfw_chunk(&u, 0, tv_image, 10, &next) == SZFW_STATUS_NOT_STARTED);
    u.board_id = 8;
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_WRONG_BOARD);
    u.board_id = 7;
    u.num_keys = 1;
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_UNKNOWN_KEY);
    u.num_keys = 2;
    memset(keys[1], 0, 32); /* empty slot */
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_UNKNOWN_KEY);
    memcpy(keys[1], tv_key, 32);
    u.max_body_size = BODY_LEN - 1;
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_TOO_LARGE);
    u.max_body_size = sizeof(f.mem);
    u.installed_version = 0x00020000;
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_DOWNGRADE);
    u.installed_version = 0;

    /* a modified body is written but never installed */
    memcpy(body, &tv_image[BODY_OFF], sizeof(body));
    body[3] ^= 0x80;
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_OK);
    CHECK(send_body(&u, body, sizeof(body)) == SZFW_STATUS_OK);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_COMMIT, NULL, 0, 0, &next, &size) == SZFW_STATUS_BAD_SIGNATURE);
    CHECK(f.installs == 0);
    /* a header raising the version is caught by the signature */
    memcpy(hdr, tv_image, sizeof(hdr));
    hdr[10] = 0x7f;
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, hdr, sizeof(hdr), 0, &next, &size) == SZFW_STATUS_OK);
    CHECK(send_body(&u, &tv_image[BODY_OFF], BODY_LEN) == SZFW_STATUS_OK);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_COMMIT, NULL, 0, 0, &next, &size) == SZFW_STATUS_BAD_SIGNATURE);
    CHECK(f.installs == 0);
    /* flash write error, abort */
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_BEGIN, tv_image, SZFW_HEADER_LEN, 0, &next, &size) ==
          SZFW_STATUS_OK);
    f.fail_write = 1;
    CHECK(szfw_chunk(&u, 0, &tv_image[BODY_OFF], 10, &next) == SZFW_STATUS_FLASH_ERROR && next == 0);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_ABORT, NULL, 0, 0, &next, &size) == SZFW_STATUS_OK);
    CHECK(szfw_boot_command(&u, SZFW_COMMAND_COMMIT, NULL, 0, 0, &next, &size) == SZFW_STATUS_NOT_STARTED);
}

int main(void)
{
    test_verify_image();
    test_update_ok();
    test_rejections();
    if (failures) {
        printf("szfw tests: %d failures\n", failures);
        return 1;
    }
    printf("szfw tests: all passed\n");
    return 0;
}
