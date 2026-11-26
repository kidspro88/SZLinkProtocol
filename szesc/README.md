# SpaceZet ESC: signed firmware over DroneCAN

Firmware for SpaceZet ESCs is updated by the flight controller over DroneCAN
(`spacezet.fw.BootCommand` / `spacezet.fw.FirmwareChunk`). Every image is
signed with Ed25519, and the ESC checks the signature against the public keys
built into it before it installs anything. A tampered image, or an image
signed by any other key, is refused, so the FC or anyone else on the bus
cannot load unsigned firmware.

## Image format (`.szfw`)

Image = 80-byte header || body (the firmware binary).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 4  | magic `SZFW` |
| 4  | 1  | format (1) |
| 5  | 1  | `key_id`: index of the signing key in the ESC's key list |
| 6  | 2  | `board_id` (u16 LE): ESC hardware type |
| 8  | 4  | `fw_version` (u32 LE): images older than the installed one are refused |
| 12 | 4  | `body_size` (u32 LE) |
| 16 | 64 | signature over `header[0..15] || body` |

The signature is EdDSA on Ed25519 with BLAKE2b (Monocypher `crypto_sign`), the
same key type ArduPilot uses for signed firmware and SZ-Link identities. The
version, board and size are covered by the signature.

## DroneCAN services (`dsdl/spacezet/fw`)

| ID | Service | Request | Response |
|---:|---------|---------|----------|
| 230 | `spacezet.fw.BootCommand` | `command` (BEGIN, COMMIT, ABORT, STATUS), `header[<=80]` | `status`, `next_offset`, `body_size` |
| 231 | `spacezet.fw.FirmwareChunk` | `offset`, `data[<=192]` | `status`, `next_offset` |

Sequence: BEGIN with the header (the ESC checks format, board, key, size and
version and erases its staging area), the body in chunks of up to 192 bytes
(each at `next_offset`; a repeated chunk is acknowledged again), then COMMIT
(the ESC reads the staged body back, checks the signature and only then
installs it). BEGIN and COMMIT are refused while the motor is armed or
running.

Note on IDs: the ESC protocol document suggests 22001/22002 for these
services, but DroneCAN service IDs are 0-255 (vendor range 200-255), so 230 and
231 are used. The message IDs it suggests (20001-20003) are already taken by
`ardupilot.indication.Button`, `ardupilot.gnss.Heading` and
`ardupilot.gnss.Status`, and need new values before they are used with
ArduPilot.

## ESC side (`c/szfw.h`)

Header-only C, Monocypher 3.1.x, no allocation. In the ESC bootloader (or an
application with a staging area):

```c
#define SZFW_IMPLEMENTATION
#include "szfw.h"

static const uint8_t trusted[][32] = { /* public keys, key_id order */ };
static szfw_updater_t upd = {
    .keys = trusted, .num_keys = 1, .board_id = 1,
    .max_body_size = STAGING_SIZE, .installed_version = INSTALLED_VERSION,
    .flash = { NULL, staging_erase, staging_write, staging_read, install_and_reboot },
};

/* BootCommand server */
status = szfw_boot_command(&upd, req.command, req.header.data, req.header.len,
                           motor_armed, &resp.next_offset, &resp.body_size);
/* FirmwareChunk server */
status = szfw_chunk(&upd, req.offset, req.data.data, req.data.len, &resp.next_offset);
```

`install_and_reboot` is only called after the signature over the staged body
has been checked. Keep the trusted keys in the bootloader (or another region
the application cannot rewrite) so a compromised application cannot replace
them. `c/test_szfw.c` covers the rejections.

## Tools (`python/`)

- `tools/szfw_sign.py --key KEY --board 1 --version 0x00010200 esc.bin esc.szfw`
  signs a binary; `--verify --pubkey HEX esc.szfw` checks an image.
  Keys are SZ-Link identity files: `szlink/python/tools/szlink_identity.py new KEY`
  (keep it offline; the ESC is built with its public key).
- `szfw.py`: image format, signing and verification.
- `sim_esc.py`: a simulated ESC on a DroneCAN bus that runs `c/szfw.h`
  (through `szfw_sim.py`, ctypes). Needs `pip install dronecan`.

## Flight controller (ArduPilot)

`AP_DroneCAN_SZFW` in the Autopilot repository: upload the image as
`szesc.szfw` with MAVLink FTP (SD card root), then set `CAN_D1_UC_SZUPD` to the
ESC's node ID while disarmed. Progress and the result are sent as STATUSTEXT
("SZFW: ESC 10 updated to 0x00010200" or "refused: bad signature"), the
parameter returns to 0, and arming is blocked while an update runs.
`Tools/scripts/szesc_update_sitl_check.py` tests this in the ArduPilot simulator with `sim_esc.py`.
