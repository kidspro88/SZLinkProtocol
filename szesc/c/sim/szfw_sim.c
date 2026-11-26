/* A simulated ESC flash for szfw.h, built as a shared library so the
 * ESC simulator (python/sim_esc.py) runs the real update code. */
#define SZFW_IMPLEMENTATION
#include "../szfw.h"

#include <stdlib.h>
#include <string.h>

#define SIM_MAX_KEYS 4u
#define SIM_FLASH_SIZE (512u * 1024u)

static uint8_t staging[SIM_FLASH_SIZE];
static uint8_t app[SIM_FLASH_SIZE];
static uint32_t staged_size;
static uint32_t app_size;
static int installs;
static uint8_t keys[SIM_MAX_KEYS][32];
static szfw_updater_t upd;

static int sim_erase(void *ctx, uint32_t size)
{
    (void)ctx;
    if (size > SIM_FLASH_SIZE) {
        return -1;
    }
    memset(staging, 0xFF, size);
    staged_size = size;
    return 0;
}

static int sim_write(void *ctx, uint32_t off, const uint8_t *d, uint32_t n)
{
    (void)ctx;
    if (off + n > staged_size) {
        return -1;
    }
    memcpy(&staging[off], d, n);
    return 0;
}

static int sim_read(void *ctx, uint32_t off, uint8_t *d, uint32_t n)
{
    (void)ctx;
    memcpy(d, &staging[off], n);
    return 0;
}

static int sim_install(void *ctx, const szfw_header_t *h)
{
    (void)ctx;
    memcpy(app, staging, h->body_size);
    app_size = h->body_size;
    installs++;
    return 0;
}

int sim_init(uint16_t board_id, const uint8_t *key_list, uint8_t num_keys, uint32_t installed_version)
{
    if (num_keys > SIM_MAX_KEYS) {
        return -1;
    }
    memset(&upd, 0, sizeof(upd));
    memset(keys, 0, sizeof(keys));
    memcpy(keys, key_list, (size_t)num_keys * 32u);
    upd.keys = (const uint8_t (*)[32])keys;
    upd.num_keys = num_keys;
    upd.board_id = board_id;
    upd.max_body_size = SIM_FLASH_SIZE;
    upd.installed_version = installed_version;
    upd.flash.erase = sim_erase;
    upd.flash.write = sim_write;
    upd.flash.read = sim_read;
    upd.flash.install = sim_install;
    installs = 0;
    app_size = 0;
    return 0;
}

uint8_t sim_boot_command(uint8_t command, const uint8_t *header, uint32_t header_len, int busy,
                         uint32_t *next_offset, uint32_t *body_size)
{
    return szfw_boot_command(&upd, command, header, header_len, busy, next_offset, body_size);
}

uint8_t sim_chunk(uint32_t offset, const uint8_t *data, uint32_t len, uint32_t *next_offset)
{
    return szfw_chunk(&upd, offset, data, len, next_offset);
}

int sim_installs(void) { return installs; }
uint32_t sim_installed_version(void) { return upd.installed_version; }
uint32_t sim_app(uint8_t *out, uint32_t max)
{
    const uint32_t n = app_size < max ? app_size : max;
    memcpy(out, app, n);
    return n;
}
