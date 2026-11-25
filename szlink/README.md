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
| SEC     | 1        | `SZ_SEC_FLAGS`: bit 0 encrypted, bit 1 FEC |
| CRC     | 2        | CRC-16/MCRF4XX (MAVLink X.25, CCITT polynomial) over LEN..SEC, then CRC_EXTRA |

Compared with MAVLink 2 the two flag bytes (incompat/compat) are replaced by
LCID, the SEC byte is added before the CRC, and the optional signature is
dropped (security is handled by the SEC layer).

## Messages (dialect `spacezet.xml`, IDs 54000–54099)

- `SZ_RC_CMD` (54000): roll, pitch, yaw (int16, ±10000) and throttle (uint16, 0–10000). LCID RC, 50–150 Hz.
- `SZ_VIDEO_PKT` (54001): H.264/H.265 NAL unit fragment, up to 248 bytes. LCID Video.
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

## Not done yet

- The SEC flags are carried and CRC-protected, but encryption (AES-256 +
  Curve25519 key exchange, rolling key) and FEC are not implemented yet.
- No Python SZ-Link frame codec yet; pymavlink can still decode the payloads.
