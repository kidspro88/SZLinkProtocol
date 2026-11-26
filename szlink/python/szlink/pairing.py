"""SZ-Link pairing (SZ_PAIR_REQUEST / SZ_PAIR_RESPONSE) and identity files.

Pairing exchanges Ed25519 identity public keys while the vehicle is
disarmed and its port is in pairing mode. Both messages carry a signature
proving the sender holds the private key. Pairing itself is trust on first
use: compare ``crypto.fingerprint`` on both sides to rule out a
man-in-the-middle during pairing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import crypto

__all__ = [
    "MSG_ID_SZ_PAIR_REQUEST",
    "MSG_ID_SZ_PAIR_RESPONSE",
    "PAIR_ACCEPTED",
    "Identity",
    "pair_request",
    "parse_pair_request",
    "pair_response",
    "parse_pair_response",
]

MSG_ID_SZ_PAIR_REQUEST = 54004
MSG_ID_SZ_PAIR_RESPONSE = 54005
PAIR_ACCEPTED, PAIR_NOT_PAIRING, PAIR_ARMED, PAIR_BAD_SIGNATURE, PAIR_FAILED = range(5)

REQ_LABEL = b"SZL pair req"
RESP_LABEL = b"SZL pair resp"


@dataclass(frozen=True)
class Identity:
    seed: bytes

    @property
    def public(self) -> bytes:
        return crypto.identity_public(self.seed)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(crypto.identity_generate())

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path, encoding="ascii") as f:
            seed = bytes.fromhex(f.read().strip())
        if len(seed) != 32:
            raise ValueError(f"{path}: not an SZ-Link identity")
        return cls(seed)

    def save(self, path: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(self.seed.hex() + "\n")


def pair_request(identity: Identity, target_system: int, target_component: int) -> bytes:
    """SZ_PAIR_REQUEST payload (98 bytes)."""
    pub = identity.public
    return bytes([target_system, target_component]) + pub + crypto.identity_sign(
        identity.seed, REQ_LABEL + pub)


def parse_pair_request(payload: bytes) -> bytes | None:
    """Vehicle side: the ground station key, or None if the signature is bad."""
    payload = bytes(payload).ljust(98, b"\0")
    pub, sig = payload[2:34], payload[34:98]
    return pub if crypto.identity_verify(pub, REQ_LABEL + pub, sig) else None


def pair_response(identity: Identity, ground_public: bytes, target_system: int,
                  target_component: int, result: int = PAIR_ACCEPTED) -> bytes:
    """Vehicle side: SZ_PAIR_RESPONSE payload (99 bytes)."""
    if result != PAIR_ACCEPTED:
        return bytes([target_system, target_component, result]) + bytes(96)
    pub = identity.public
    sig = crypto.identity_sign(identity.seed, RESP_LABEL + pub + ground_public)
    return bytes([target_system, target_component, result]) + pub + sig


def parse_pair_response(payload: bytes, ground_public: bytes) -> tuple[int, bytes | None]:
    """``(result, vehicle_public)``; vehicle_public is None unless the pairing
    was accepted and the vehicle's signature is valid."""
    payload = bytes(payload).ljust(99, b"\0")
    result, pub, sig = payload[2], payload[3:35], payload[35:99]
    if result != PAIR_ACCEPTED:
        return result, None
    if not crypto.identity_verify(pub, RESP_LABEL + pub + ground_public, sig):
        return PAIR_BAD_SIGNATURE, None
    return result, pub
