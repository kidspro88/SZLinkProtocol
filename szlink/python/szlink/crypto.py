"""SZ-Link cryptographic primitives and the Noise_IK handshake.

Everything here is byte-for-byte compatible with ``szlink/c/szlink_sec.h``:

* HMAC-BLAKE2b (RFC 2104 with BLAKE2b-512, block size 128) and HKDF on top
  of it, as used by the Noise framework.
* ChaCha20-Poly1305 (RFC 8439) with a tag that may be truncated to 8 bytes.
* ``Noise_IK_25519_ChaChaPoly_BLAKE2b``. The first message carries an
  8-byte little-endian timestamp (microseconds, strictly increasing) so the
  responder can reject a replayed KEX_INIT; the second has an empty payload. The initiator (ground station) knows the responder's (vehicle's)
  static public key; the responder accepts only the one paired initiator key.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

__all__ = [
    "AuthError",
    "KEY_LEN",
    "HASH_LEN",
    "KEX_INIT_LEN",
    "KEX_RESP_LEN",
    "PROLOGUE",
    "hmac_blake2b",
    "hkdf",
    "hkdf_expand32",
    "aead_seal",
    "aead_open",
    "x25519",
    "x25519_public",
    "keys_from_secret",
    "keys_from_passphrase",
    "HandshakeInitiator",
    "HandshakeResponder",
]

KEY_LEN = 32
HASH_LEN = 64
TAG_LEN = 16
KEX_TIMESTAMP_LEN = 8
KEX_INIT_LEN = 32 + (32 + TAG_LEN) + KEX_TIMESTAMP_LEN + TAG_LEN  # e, enc(s), enc(timestamp)
KEX_RESP_LEN = 32 + TAG_LEN  # e, enc(empty payload)
PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2b"
PROLOGUE = b"SZ-Link v1"


class AuthError(Exception):
    """Authentication failed (bad tag or bad handshake)."""


# --- hashing ------------------------------------------------------------------

def hmac_blake2b(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2b).digest()


def hkdf(chaining_key: bytes, ikm: bytes, n: int) -> list[bytes]:
    """Noise HKDF: returns ``n`` (2 or 3) outputs of HASH_LEN bytes."""
    temp = hmac_blake2b(chaining_key, ikm)
    out = []
    prev = b""
    for i in range(1, n + 1):
        prev = hmac_blake2b(temp, prev + bytes([i]))
        out.append(prev)
    return out


def hkdf_expand32(prk: bytes, info: bytes) -> bytes:
    """HKDF-Expand(PRK, info, L=32) with HMAC-BLAKE2b (a single block)."""
    return hmac_blake2b(prk, info + b"\x01")[:KEY_LEN]


# --- ChaCha20-Poly1305 (RFC 8439) --------------------------------------------

def _chacha20(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    full_nonce = struct.pack("<I", counter) + nonce
    enc = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None).encryptor()
    return enc.update(data)


def _poly_tag(key: bytes, nonce: bytes, ad: bytes, ct: bytes) -> bytes:
    otk = _chacha20(key, nonce, 0, bytes(32))

    def pad16(b: bytes) -> bytes:
        return bytes(-len(b) % 16)

    mac_data = ad + pad16(ad) + ct + pad16(ct) + struct.pack("<QQ", len(ad), len(ct))
    return poly1305.Poly1305.generate_tag(otk, mac_data)


def aead_seal(key: bytes, nonce: bytes, ad: bytes, plaintext: bytes,
              tag_len: int = TAG_LEN) -> tuple[bytes, bytes]:
    """Encrypt; returns ``(ciphertext, tag[:tag_len])``."""
    ct = _chacha20(key, nonce, 1, plaintext)
    return ct, _poly_tag(key, nonce, ad, ct)[:tag_len]


def aead_open(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Verify the (possibly truncated) tag and decrypt, or raise AuthError."""
    if len(tag) not in (8, TAG_LEN):
        raise AuthError("bad tag length")
    expect = _poly_tag(key, nonce, ad, ciphertext)[: len(tag)]
    if not hmac.compare_digest(expect, tag):
        raise AuthError("bad tag")
    return _chacha20(key, nonce, 1, ciphertext)


# --- X25519 -------------------------------------------------------------------

def x25519(private: bytes, public: bytes) -> bytes:
    try:
        shared = X25519PrivateKey.from_private_bytes(private).exchange(
            X25519PublicKey.from_public_bytes(public))
    except ValueError as exc:  # low-order point
        raise AuthError("bad public key") from exc
    if shared == bytes(32):
        raise AuthError("low-order public key")
    return shared


def x25519_public(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def keys_from_secret(secret: bytes) -> tuple[bytes, bytes]:
    """``(vehicle_private, ground_private)`` derived from a shared 32-byte secret.

    The secret is the MAVLink 2 signing key, so a vehicle is paired with the
    ground station that set up signing on it.
    """
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    return hkdf_expand32(secret, b"SZL vehicle key"), hkdf_expand32(secret, b"SZL ground key")


def keys_from_passphrase(passphrase: str) -> tuple[bytes, bytes]:
    """Same as MAVProxy ``signing setup <passphrase>``: secret = SHA-256(passphrase)."""
    return keys_from_secret(hashlib.sha256(passphrase.encode()).digest())


def x25519_generate() -> bytes:
    return X25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())


# --- Noise_IK -----------------------------------------------------------------

class _Symmetric:
    """Noise SymmetricState + CipherState."""

    def __init__(self, responder_static: bytes) -> None:
        self.h = PROTOCOL_NAME.ljust(HASH_LEN, b"\x00")
        self.ck = self.h
        self.k: bytes | None = None
        self.n = 0
        self.mix_hash(PROLOGUE)
        self.mix_hash(responder_static)  # pre-message: <- s

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.blake2b(self.h + data).digest()

    def mix_key(self, ikm: bytes) -> None:
        self.ck, temp_k = hkdf(self.ck, ikm, 2)
        self.k = temp_k[:KEY_LEN]
        self.n = 0

    def _nonce(self) -> bytes:
        return b"\x00\x00\x00\x00" + struct.pack("<Q", self.n)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        assert self.k is not None
        ct, tag = aead_seal(self.k, self._nonce(), self.h, plaintext)
        self.n += 1
        out = ct + tag
        self.mix_hash(out)
        return out

    def decrypt_and_hash(self, data: bytes) -> bytes:
        assert self.k is not None
        pt = aead_open(self.k, self._nonce(), self.h, data[:-TAG_LEN], data[-TAG_LEN:])
        self.n += 1
        self.mix_hash(data)
        return pt

    def split(self) -> tuple[bytes, bytes]:
        k1, k2 = hkdf(self.ck, b"", 2)
        return k1[:KEY_LEN], k2[:KEY_LEN]


class HandshakeInitiator:
    """Ground-station side: ``-> e, es, s, ss`` then ``<- e, ee, se``."""

    def __init__(self, static_private: bytes, responder_public: bytes,
                 ephemeral_private: bytes | None = None) -> None:
        self.s = static_private
        self.rs = responder_public
        self.e = ephemeral_private if ephemeral_private is not None else x25519_generate()
        self.sym = _Symmetric(responder_public)

    def write_init(self, timestamp_us: int) -> bytes:
        sym = self.sym
        e_pub = x25519_public(self.e)
        sym.mix_hash(e_pub)
        sym.mix_key(x25519(self.e, self.rs))           # es
        enc_s = sym.encrypt_and_hash(x25519_public(self.s))
        sym.mix_key(x25519(self.s, self.rs))           # ss
        payload = sym.encrypt_and_hash(struct.pack("<Q", timestamp_us))
        return e_pub + enc_s + payload

    def read_resp(self, msg: bytes) -> tuple[bytes, bytes]:
        """Returns ``(key initiator->responder, key responder->initiator)``."""
        if len(msg) != KEX_RESP_LEN:
            raise AuthError("bad KEX_RESP length")
        msg = bytes(msg)
        sym = self.sym
        re = msg[:32]
        sym.mix_hash(re)
        sym.mix_key(x25519(self.e, re))                # ee
        sym.mix_key(x25519(self.s, re))                # se
        sym.decrypt_and_hash(msg[32:])
        return sym.split()


class HandshakeResponder:
    """Vehicle side: accepts only ``allowed_initiator`` as the remote static key."""

    def __init__(self, static_private: bytes, allowed_initiator: bytes) -> None:
        self.s = static_private
        self.allowed = allowed_initiator

    def respond(self, msg: bytes, ephemeral_private: bytes | None = None
                ) -> tuple[bytes, bytes, bytes, int]:
        """Process KEX_INIT; returns ``(kex_resp, key i->r, key r->i, timestamp_us)``."""
        if len(msg) != KEX_INIT_LEN:
            raise AuthError("bad KEX_INIT length")
        msg = bytes(msg)
        sym = _Symmetric(x25519_public(self.s))
        re = msg[:32]
        sym.mix_hash(re)
        sym.mix_key(x25519(self.s, re))                # es
        rs = sym.decrypt_and_hash(msg[32:80])
        if not hmac.compare_digest(rs, self.allowed):
            raise AuthError("initiator is not the paired ground station")
        sym.mix_key(x25519(self.s, rs))                # ss
        (timestamp,) = struct.unpack("<Q", sym.decrypt_and_hash(msg[80:]))
        e = ephemeral_private if ephemeral_private is not None else x25519_generate()
        e_pub = x25519_public(e)
        sym.mix_hash(e_pub)
        sym.mix_key(x25519(e, re))                     # ee
        sym.mix_key(x25519(e, rs))                     # se
        payload = sym.encrypt_and_hash(b"")
        k1, k2 = sym.split()
        return e_pub + payload, k1, k2, timestamp
