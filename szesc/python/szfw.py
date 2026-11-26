"""SpaceZet ESC signed firmware images (see szesc/README.md, c/szfw.h).

Image = 80-byte header || body; the header ends with an EdDSA (Ed25519 +
BLAKE2b, Monocypher crypto_sign) signature over header[0:16] || body.
Keys are SZ-Link identities (``szlink.pairing.Identity``, a hex seed file).
"""

from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass

try:
    from szlink import crypto
except ImportError:  # running from the repository
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "szlink", "python"))
    from szlink import crypto

HEADER_LEN = 80
SIGNED_HEADER_LEN = 16
FORMAT = 1
MAGIC = b"SZFW"
CHUNK_MAX = 192

(STATUS_OK, STATUS_BUSY, STATUS_BAD_HEADER, STATUS_WRONG_BOARD, STATUS_UNKNOWN_KEY,
 STATUS_TOO_LARGE, STATUS_DOWNGRADE, STATUS_NOT_STARTED, STATUS_BAD_OFFSET,
 STATUS_INCOMPLETE, STATUS_BAD_SIGNATURE, STATUS_FLASH_ERROR) = range(12)
STATUS_NAMES = ["OK", "BUSY", "BAD_HEADER", "WRONG_BOARD", "UNKNOWN_KEY", "TOO_LARGE",
                "DOWNGRADE", "NOT_STARTED", "BAD_OFFSET", "INCOMPLETE", "BAD_SIGNATURE",
                "FLASH_ERROR"]
COMMAND_BEGIN, COMMAND_COMMIT, COMMAND_ABORT, COMMAND_STATUS = range(4)


@dataclass(frozen=True)
class Header:
    key_id: int
    board_id: int
    fw_version: int
    body_size: int
    signature: bytes = bytes(64)

    def signed_part(self) -> bytes:
        return MAGIC + struct.pack("<BBHII", FORMAT, self.key_id, self.board_id,
                                   self.fw_version, self.body_size)

    def pack(self) -> bytes:
        return self.signed_part() + self.signature

    @classmethod
    def parse(cls, data: bytes) -> "Header":
        if len(data) < HEADER_LEN or data[:4] != MAGIC or data[4] != FORMAT:
            raise ValueError("not an SZFW image")
        key_id, board_id, version, size = struct.unpack_from("<BHII", data, 5)
        return cls(key_id, board_id, version, size, bytes(data[16:80]))


def sign_image(seed: bytes, body: bytes, board_id: int, fw_version: int, key_id: int = 0) -> bytes:
    hdr = Header(key_id, board_id, fw_version, len(body))
    sig = crypto.identity_sign(seed, hdr.signed_part() + body)
    return Header(key_id, board_id, fw_version, len(body), sig).pack() + body


def verify_image(image: bytes, keys: list[bytes]) -> int:
    """STATUS_OK if the image is signed by keys[key_id]; same rules as szfw_verify_image."""
    try:
        hdr = Header.parse(image)
    except ValueError:
        return STATUS_BAD_HEADER
    if hdr.body_size != len(image) - HEADER_LEN:
        return STATUS_INCOMPLETE
    if hdr.key_id >= len(keys) or not any(keys[hdr.key_id]):
        return STATUS_UNKNOWN_KEY
    ok = crypto.identity_verify(keys[hdr.key_id], image[:SIGNED_HEADER_LEN] + image[HEADER_LEN:],
                                hdr.signature)
    return STATUS_OK if ok else STATUS_BAD_SIGNATURE
