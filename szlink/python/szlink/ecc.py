"""SZ-Link FEC: Reed-Solomon forward error correction envelope.

Wraps a complete MAVLink v1/v2 frame (or any byte string up to 65535 bytes)
in an error-correcting envelope so that byte errors introduced on a noisy
radio link can be repaired by the receiver before the frame reaches the
MAVLink parser.

Wire format of one ECC frame::

    +-------------------------+----------------------------------------+
    | header codeword (7 B)   | body codewords                         |
    | 0xEC len_lo len_hi + 4  | ceil(len / k) blocks, each             |
    | parity bytes            | min(k, remaining) data + nsym parity   |
    +-------------------------+----------------------------------------+

* Code: Reed-Solomon over GF(2^8), primitive polynomial 0x11D, generator
  roots alpha^0 .. alpha^(nsym-1) (fcr = 0), systematic, parity appended.
* The header is a shortened RS(7,3) codeword: it corrects up to 2 byte
  errors, including in the 0xEC sync byte.
* Body blocks are shortened RS(k + nsym, k) codewords with k = 255 - nsym.
  Each block corrects up to nsym // 2 byte errors. ``nsym`` is a link
  parameter that both ends must agree on (default 16, i.e. up to 8 byte
  errors per block; a full MAVLink 2 frame of 280 bytes needs 2 blocks).
"""

from __future__ import annotations

__all__ = [
    "ECCError",
    "RSCodec",
    "SZLinkECC",
    "MAGIC",
    "HEADER_NSYM",
    "HEADER_LEN",
    "DEFAULT_NSYM",
]

MAGIC = 0xEC
HEADER_DATA_LEN = 3
HEADER_NSYM = 4
HEADER_LEN = HEADER_DATA_LEN + HEADER_NSYM
DEFAULT_NSYM = 16
PRIM_POLY = 0x11D


class ECCError(Exception):
    """Raised when a codeword has more errors than the code can correct."""


# --- GF(2^8) arithmetic -------------------------------------------------------

GF_EXP = [0] * 512
GF_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        GF_EXP[i] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= PRIM_POLY
    for i in range(255, 512):
        GF_EXP[i] = GF_EXP[i - 255]


_init_tables()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] + 255 - GF_LOG[b]) % 255]


def gf_pow(a: int, n: int) -> int:
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] * n) % 255]


def gf_inv(a: int) -> int:
    return gf_div(1, a)


# Polynomials are lists of coefficients, highest degree first.

def poly_scale(p: list[int], x: int) -> list[int]:
    return [gf_mul(c, x) for c in p]


def poly_add(p: list[int], q: list[int]) -> list[int]:
    r = [0] * max(len(p), len(q))
    for i, c in enumerate(p):
        r[i + len(r) - len(p)] = c
    for i, c in enumerate(q):
        r[i + len(r) - len(q)] ^= c
    return r


def poly_mul(p: list[int], q: list[int]) -> list[int]:
    r = [0] * (len(p) + len(q) - 1)
    for j, qc in enumerate(q):
        for i, pc in enumerate(p):
            r[i + j] ^= gf_mul(pc, qc)
    return r


def poly_eval(p: list[int], x: int) -> int:
    y = p[0]
    for c in p[1:]:
        y = gf_mul(y, x) ^ c
    return y


# --- Reed-Solomon codec -------------------------------------------------------

class RSCodec:
    """Systematic Reed-Solomon codec with ``nsym`` parity bytes per codeword."""

    def __init__(self, nsym: int) -> None:
        if not 2 <= nsym <= 254 or nsym % 2:
            raise ValueError("nsym must be an even number in [2, 254]")
        self.nsym = nsym
        g = [1]
        for i in range(nsym):
            g = poly_mul(g, [1, GF_EXP[i]])
        self.generator = g

    @property
    def max_data(self) -> int:
        return 255 - self.nsym

    def encode(self, data: bytes) -> bytes:
        """Return ``data`` followed by ``nsym`` parity bytes."""
        if len(data) > self.max_data:
            raise ValueError("data too long for one codeword")
        g = self.generator
        rem = list(data) + [0] * self.nsym
        for i in range(len(data)):
            coef = rem[i]
            if coef:
                for j in range(1, len(g)):
                    rem[i + j] ^= gf_mul(g[j], coef)
        return bytes(data) + bytes(rem[len(data):])

    def syndromes(self, msg: list[int]) -> list[int]:
        return [poly_eval(msg, GF_EXP[i]) for i in range(self.nsym)]

    def decode(self, codeword: bytes) -> tuple[bytes, int]:
        """Correct ``codeword`` in place.

        Returns ``(data, n_corrected)``. Raises :class:`ECCError` if the
        codeword is uncorrectable.
        """
        n = len(codeword)
        if n <= self.nsym or n > 255:
            raise ValueError("invalid codeword length")
        msg = list(codeword)
        synd = self.syndromes(msg)
        if not any(synd):
            return bytes(msg[: n - self.nsym]), 0

        # Berlekamp-Massey: find the error locator polynomial.
        # ``synd_p`` is padded with a leading zero so that index K - j never
        # goes negative.
        synd_p = [0] + synd
        err_loc = [1]
        old_loc = [1]
        for i in range(self.nsym):
            k = i + 1
            delta = synd_p[k]
            for j in range(1, len(err_loc)):
                delta ^= gf_mul(err_loc[-(j + 1)], synd_p[k - j])
            old_loc = old_loc + [0]
            if delta:
                if len(old_loc) > len(err_loc):
                    new_loc = poly_scale(old_loc, delta)
                    old_loc = poly_scale(err_loc, gf_inv(delta))
                    err_loc = new_loc
                err_loc = poly_add(err_loc, poly_scale(old_loc, delta))
        while err_loc and err_loc[0] == 0:
            err_loc.pop(0)
        n_err = len(err_loc) - 1
        if n_err * 2 > self.nsym:
            raise ECCError("too many errors")

        # Chien search: roots of the (reversed) locator give error positions.
        rev_loc = err_loc[::-1]
        err_pos = [n - 1 - i for i in range(n) if poly_eval(rev_loc, GF_EXP[i]) == 0]
        if len(err_pos) != n_err:
            raise ECCError("could not locate errors")

        # Forney algorithm: error magnitudes.
        coef_pos = [n - 1 - p for p in err_pos]
        loc = [1]
        for p in coef_pos:
            loc = poly_add(poly_mul(loc, [GF_EXP[p], 0]), loc)
        omega = poly_mul(synd_p[::-1], loc)
        omega = omega[len(omega) - len(loc):]
        x = [GF_EXP[p] for p in coef_pos]
        for i, xi in enumerate(x):
            xi_inv = gf_inv(xi)
            denom = 1
            for j, xj in enumerate(x):
                if j != i:
                    denom = gf_mul(denom, 1 ^ gf_mul(xi_inv, xj))
            if denom == 0:
                raise ECCError("Forney denominator is zero")
            y = gf_mul(xi, poly_eval(omega, xi_inv))  # X^(1 - fcr), fcr = 0
            msg[err_pos[i]] ^= gf_div(y, denom)

        if any(self.syndromes(msg)):
            raise ECCError("correction failed")
        return bytes(msg[: n - self.nsym]), n_err


# --- SZ-Link framing ----------------------------------------------------------

class SZLinkECC:
    """Encode and decode SZ-Link ECC frames around MAVLink frames."""

    def __init__(self, nsym: int = DEFAULT_NSYM) -> None:
        self.body = RSCodec(nsym)
        self.header = RSCodec(HEADER_NSYM)
        self._buf = bytearray()
        self.stats = {"frames": 0, "corrected_bytes": 0, "failed": 0}

    @property
    def nsym(self) -> int:
        return self.body.nsym

    def encoded_length(self, payload_len: int) -> int:
        k = self.body.max_data
        blocks = -(-payload_len // k)
        return HEADER_LEN + payload_len + blocks * self.nsym

    def encode(self, payload: bytes) -> bytes:
        if len(payload) > 0xFFFF:
            raise ValueError("payload too long")
        out = bytearray(
            self.header.encode(bytes([MAGIC, len(payload) & 0xFF, len(payload) >> 8]))
        )
        k = self.body.max_data
        for i in range(0, len(payload), k):
            out += self.body.encode(payload[i : i + k])
        return bytes(out)

    def _decode_header(self, data: bytes) -> tuple[int, int]:
        hdr, fixed = self.header.decode(data[:HEADER_LEN])
        if hdr[0] != MAGIC:
            raise ECCError("bad magic")
        return hdr[1] | (hdr[2] << 8), fixed

    def decode(self, frame: bytes) -> tuple[bytes, int]:
        """Decode one complete ECC frame. Returns ``(payload, n_corrected)``."""
        if len(frame) < HEADER_LEN:
            raise ECCError("frame too short")
        length, fixed = self._decode_header(frame)
        if len(frame) < self.encoded_length(length):
            raise ECCError("frame truncated")
        out = bytearray()
        pos = HEADER_LEN
        k = self.body.max_data
        remaining = length
        while remaining:
            dlen = min(k, remaining)
            data, n = self.body.decode(frame[pos : pos + dlen + self.nsym])
            out += data
            fixed += n
            pos += dlen + self.nsym
            remaining -= dlen
        return bytes(out), fixed

    def feed(self, data: bytes) -> list[bytes]:
        """Stream decoder: feed received bytes, get back decoded payloads.

        Resynchronises after garbage or uncorrectable frames by sliding one
        byte at a time and trying to decode a header at each position.
        """
        self._buf += data
        out = []
        while len(self._buf) >= HEADER_LEN:
            try:
                length, _ = self._decode_header(bytes(self._buf[:HEADER_LEN]))
            except ECCError:
                del self._buf[0]
                continue
            total = self.encoded_length(length)
            if len(self._buf) < total:
                break
            try:
                payload, fixed = self.decode(bytes(self._buf[:total]))
            except ECCError:
                self.stats["failed"] += 1
                del self._buf[0]
                continue
            del self._buf[:total]
            self.stats["frames"] += 1
            self.stats["corrected_bytes"] += fixed
            out.append(payload)
        return out
