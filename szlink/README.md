# SZ-Link

SZ-Link is SpaceZet's SDR link protocol. It reuses the MAVLink 2 message set and
payload encoding, and adds a **logical channel** (LCID) and a **security flag
byte** (SEC) so that RC, telemetry and video share one RF link with clear QoS.

## Frame format

| Field   | Size     | Notes |
|---------|----------|-------|
| STX     | 1        | `0xFD` |
| LEN     | 1        | payload length (MAVLink 2 trailing-zero trimming applies) |
| LCID    | 1        | `SZ_LCID`: 0 = RC, 1 = Telemetry, 2 = Video |
| SEQ     | 1        | sequence number |
| SYSID   | 1        | system ID |
| COMPID  | 1        | component ID |
| MSGID   | 3        | message ID, little-endian |
| PAYLOAD | 0–255    | MAVLink 2 payload encoding |
| SEC     | 1        | `SZ_SEC_FLAGS`: bit 0 encrypted, bits 1-2 key epoch, bit 3 FEC, bit 4 signed |
| TAG     | 0/8/16   | only if SEC bit 0 or 4: 8 bytes on LCID RC, 16 otherwise |
| CRC     | 2        | CRC-16/MCRF4XX (MAVLink X.25, CCITT polynomial) over LEN..TAG, then CRC_EXTRA |

Compared with MAVLink 2 the two flag bytes (incompat/compat) are replaced by
LCID, the SEC byte (and the tag of protected frames) is added before the CRC,
and the MAVLink signature is dropped: authentication is done by the SEC layer.

## Messages (dialect `spacezet.xml`, IDs 54000–54099)

- `SZ_RC_CMD` (54000): roll, pitch, yaw (int16, ±10000) and throttle (uint16, 0–10000). LCID RC, 50–150 Hz.
- `SZ_VIDEO_PKT` (54001): H.264/H.265 NAL unit fragment, up to 248 bytes. LCID Video.
- `SZ_KEX_INIT` (54002) / `SZ_KEX_RESP` (54003): key exchange (see Security). LCID Telemetry, always unprotected.
- Telemetry uses the standard MAVLink messages from `common.xml` (HEARTBEAT, GPS_RAW_INT, ...).

## C library

The C API is the MAVLink C API with every `mavlink`/`MAVLINK` prefix renamed to
`szlink`/`SZLINK`, plus the frame layer in `szlink_frame.h`. `MAV_*` enum
values keep their names.

```bash
pip install -r pymavlink/requirements.txt
python3 scripts/szlinkgen.py --output build/szlink   # generate
./scripts/test_szlink.sh                              # generate + test
```

```c
#include "spacezet/szlink.h"
#include "szlink_frame.h"

szlink_message_t msg;
uint8_t buf[SZLINK_FRAME_MAX_LEN];
szlink_msg_sz_rc_cmd_pack(sysid, compid, &msg, 1, 1, roll, pitch, yaw, throttle);
uint16_t n = szlink_frame_serialize(buf, &msg, SZ_LCID_RC, 0);
/* send buf[0..n) */

szlink_frame_parser_t parser;
szlink_frame_parser_init(&parser);
/* for each received byte c: */
uint8_t lcid, sec;
if (szlink_frame_parse_char(&parser, c, &msg, &lcid, &sec)) {
    if (msg.msgid == SZLINK_MSG_ID_SZ_RC_CMD) {
        szlink_sz_rc_cmd_t cmd;
        szlink_msg_sz_rc_cmd_decode(&msg, &cmd);
    }
}
```

## Security

| SEC bits | Meaning |
|----------|---------|
| 0 (`0x01`) | encrypted + authenticated (ChaCha20-Poly1305) |
| 1-2 (`0x06`) | key epoch modulo 4 |
| 3 (`0x08`) | frame is inside a Reed-Solomon FEC envelope |
| 4 (`0x10`) | signed: payload in clear, authenticated with the same AEAD |

**Pairing.** The ground station (initiator) and the vehicle (responder) each have
a static X25519 key pair. The ground station knows the vehicle's public key and
the vehicle accepts only its paired ground station. The keys can be any X25519
keys; the ArduPilot port derives both from the MAVLink 2 signing key the
vehicle and ground station already share (`szlink_sec_keys_from_secret`,
`crypto.keys_from_passphrase` = SHA-256 of the MAVProxy `signing setup`
passphrase), so pairing is the existing signing setup over USB.

**Handshake.** `Noise_IK_25519_ChaChaPoly_BLAKE2b`, prologue `SZ-Link v1`. The
ground station sends `SZ_KEX_INIT` (104 bytes: `-> e, es, s, ss` plus an 8-byte
timestamp that must increase, so a recorded KEX_INIT cannot be replayed); the
vehicle answers `SZ_KEX_RESP` (48 bytes: `<- e, ee, se`). Each side derives two
32-byte chain keys, one per direction. The vehicle keeps using its old session
until the first frame protected with the new keys arrives (key confirmation),
and both sides accept the previous session for 5 s after a rekey.

**Rekey.** The ground station runs a new handshake every 10 minutes (fresh
ECDH, forward secrecy), or after 5 s without an authenticated frame from the
vehicle (for example after a reboot). A session older than 12 minutes is not
used any more.

**Key ratchet (every 30 s, nothing on air).** Both ends count epochs from the
session start on their own clock: `epoch = elapsed / 30 s`. At each epoch the
chain key is replaced by `HKDF-Expand(chain, "SZL chain")` and the old one is
wiped, so a key captured later cannot decrypt older traffic. The key of a
logical channel is `HKDF-Expand(chain, "SZL lcid" || lcid)`: RC, telemetry and
video never share a key, and each direction has its own chain. HKDF uses
HMAC-BLAKE2b. The SEC byte carries `epoch mod 4`; the receiver picks the epoch
nearest to its own estimate, so clock skew at a boundary and late frames of
the previous epoch work.

**Frames.** Nonce = epoch (u32 LE) | LCID | 3 zero bytes | counter (u32 LE).
The counter starts at 0 for each channel and epoch and is implicit: only its
low byte is sent, in SEQ, and the receiver reconstructs the rest (it also
tries the next 16 x 256 values after a long loss). Associated data = header
(STX..MSGID) || SEC, plus the payload for signed-only frames. A 64-frame
window per channel rejects replays and accepts reordering. The tag is 8 bytes
on RC (latency, small frames) and 16 bytes elsewhere.

**FEC.** Video frames can be sent inside the Reed-Solomon envelope of
`szlink_ecc.h` / `szlink/python/szlink/ecc.py` (starts with `0xEC`, RS(7,3)
header, body blocks of up to `255 - nsym` bytes with `nsym` parity bytes, i.e.
up to `nsym / 2` corrected bytes per block). FEC is applied after encryption;
the FEC bit is authenticated and must match how the frame arrived. Both ends
must use the same `nsym` (2-32, even).

### C (embedded peers)

```c
#define SZLINK_SEC_IMPLEMENTATION   /* in one .c file */
#define SZLINK_ECC_IMPLEMENTATION
#include "spacezet/szlink.h"
#include "szlink_frame.h"

szlink_sec_t sec;
szlink_sec_init(&sec, SZLINK_SEC_RESPONDER, my_private_key, peer_public_key);
/* on SZ_KEX_INIT: szlink_sec_handle_kex_init(&sec, init, random_32_bytes, now_ms, resp) */
n = szlink_frame_serialize_secure(buf, &msg, SZ_LCID_RC, SZLINK_SEC_ENCRYPTED, 0, &sec, now_ms);

parser.sec = &sec;          /* protected frames are verified and decrypted */
parser.fec_nsym = 16;       /* accept FEC envelopes */
parser.now_ms = now_ms;     /* before feeding bytes */
```

It needs [Monocypher](https://monocypher.org) 3.1.x (a copy is in
`c/third_party/monocypher`, the same version ArduPilot ships). The library
reads no clock and no RNG: pass a monotonic millisecond time and 32 random
bytes for each ephemeral key.

### Python (ground station)

`szlink/python/szlink` (needs `cryptography`):

```python
from szlink import FrameCodec, SecureLink
from szlink.session import INITIATOR, SEC_ENCRYPTED

link = SecureLink(INITIATOR, gcs_private_key, vehicle_public_key)
codec = FrameCodec(msg_info, link, fec_nsym=16)   # msg_info(msgid) -> (crc_extra, max_len)
if link.needs_kex(now_ms):
    send(codec.encode(54002, bytes([1, 1]) + link.kex_init(now_ms), 255, 190, 1))
for frame in codec.parse(received, now_ms):
    if frame.msgid == 54003:
        link.handle_kex_resp(frame.payload[2:50], now_ms)
send(codec.encode(54000, rc_payload, 255, 190, 0, mode=SEC_ENCRYPTED, now_ms=now_ms))
```

`szlink/python/tools/gen_c_vectors.py` writes the vectors the C tests use to
check that both implementations produce identical bytes.
