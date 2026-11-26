"""SZ-Link secure session: key ratchet, per-channel keys, replay protection.

Byte-for-byte compatible with ``szlink/c/szlink_sec.h``. See
``szlink/README.md`` ("Security") for the protocol description.

Time is passed in by the caller as milliseconds from any monotonic clock;
nothing here reads a clock or a random number generator except
``x25519_generate`` when no ephemeral key is supplied.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from . import crypto
from .crypto import AuthError

__all__ = [
    "AuthError",
    "SecureLink",
    "INITIATOR",
    "RESPONDER",
    "SEC_ENCRYPTED",
    "SEC_EPOCH_MASK",
    "SEC_EPOCH_SHIFT",
    "SEC_FEC",
    "SEC_SIGNED",
    "MODE_SIGN",
    "MODE_ENCRYPT",
    "EPOCH_MS",
    "REKEY_MS",
    "SESSION_MAX_MS",
    "tag_len",
]

# SEC byte (SZ_SEC_FLAGS)
SEC_ENCRYPTED = 0x01
SEC_EPOCH_SHIFT = 1
SEC_EPOCH_MASK = 0x06
SEC_FEC = 0x08
SEC_SIGNED = 0x10

MODE_SIGN = SEC_SIGNED
MODE_ENCRYPT = SEC_ENCRYPTED

INITIATOR = "initiator"
RESPONDER = "responder"

NUM_LCID = 3
LCID_RC = 0
EPOCH_MS = 30_000             # key ratchet period
REKEY_MS = 600_000            # initiator starts a new handshake after this
SESSION_MAX_MS = 720_000      # a session is unusable after this
PREV_SESSION_GRACE_MS = 5_000  # old session still accepted (RX) after a rekey
KEX_RETRY_MS = 1_000          # initiator resends KEX_INIT if unanswered
RX_IDLE_REKEY_MS = 5_000      # initiator rekeys if nothing authenticates for this long
REPLAY_WINDOW = 64
COUNTER_SEARCH = 16           # extra 256-frame steps tried after a long loss
HEADER_LEN = 9

_LABEL_CHAIN = b"SZL chain"
_LABEL_LCID = b"SZL lcid"


def tag_len(lcid: int) -> int:
    """Authentication tag length: 8 bytes for RC (latency), 16 otherwise."""
    return 8 if lcid == LCID_RC else 16


def nonce(epoch: int, lcid: int, counter: int) -> bytes:
    return struct.pack("<IB3xI", epoch, lcid, counter)


def _epoch_keys(chain: bytes) -> list[bytes]:
    return [crypto.hkdf_expand32(chain, _LABEL_LCID + bytes([lcid])) for lcid in range(NUM_LCID)]


def _next_chain(chain: bytes) -> bytes:
    return crypto.hkdf_expand32(chain, _LABEL_CHAIN)


class ReplayWindow:
    """Sliding window over the 32-bit implicit frame counter."""

    def __init__(self) -> None:
        self.top = -1   # highest accepted counter, -1 = none yet
        self.bits = 0   # bit i set = counter (top - i) accepted

    def candidates(self, seq: int) -> list[int]:
        """Counters whose low byte is ``seq``, most likely first."""
        base = self.top + 1
        c = (base & ~0xFF) | seq
        if c < base - 128:
            c += 256
        elif c > base + 127 and c >= 256:
            c -= 256
        return [c + 256 * k for k in range(COUNTER_SEARCH + 1) if c + 256 * k < 1 << 32]

    def fresh(self, c: int) -> bool:
        if c > self.top:
            return True
        off = self.top - c
        return off < REPLAY_WINDOW and not (self.bits >> off) & 1

    def accept(self, c: int) -> None:
        if c > self.top:
            shift = c - self.top
            self.bits = ((self.bits << shift) | 1) & ((1 << REPLAY_WINDOW) - 1)
            self.top = c
        else:
            self.bits |= 1 << (self.top - c)


@dataclass
class _Epoch:
    epoch: int
    keys: list[bytes]
    windows: list[ReplayWindow] = field(
        default_factory=lambda: [ReplayWindow() for _ in range(NUM_LCID)])


class _TxChain:
    def __init__(self, chain: bytes) -> None:
        self.chain = chain
        self.epoch = 0
        self.keys = _epoch_keys(chain)
        self.counters = [0] * NUM_LCID

    def advance_to(self, epoch: int) -> None:
        while self.epoch < epoch:
            self.chain = _next_chain(self.chain)
            self.epoch += 1
        self.keys = _epoch_keys(self.chain)
        self.counters = [0] * NUM_LCID


class _RxChain:
    def __init__(self, chain: bytes) -> None:
        self.chain = chain
        self.cur = _Epoch(0, _epoch_keys(chain))
        self.prev: _Epoch | None = None

    def open(self, header: bytes, payload: bytes, sec: int, tag: bytes,
             epoch: int) -> bytes:
        if epoch == self.cur.epoch:
            return _open_in(self.cur, header, payload, sec, tag)
        if self.prev is not None and epoch == self.prev.epoch:
            return _open_in(self.prev, header, payload, sec, tag)
        if epoch < self.cur.epoch:
            raise AuthError("epoch too old")
        # ratchet forward on a copy; commit only if the frame authenticates
        chain = self.chain
        before = None
        for e in range(self.cur.epoch, epoch):
            if e == epoch - 1:
                before = _Epoch(e, _epoch_keys(chain)) if e != self.cur.epoch else self.cur
            chain = _next_chain(chain)
        candidate = _Epoch(epoch, _epoch_keys(chain))
        plain = _open_in(candidate, header, payload, sec, tag)
        self.chain = chain
        self.prev = before
        self.cur = candidate
        return plain


def _open_in(ep: _Epoch, header: bytes, payload: bytes, sec: int, tag: bytes) -> bytes:
    lcid, seq = header[2], header[3]
    window = ep.windows[lcid]
    key = ep.keys[lcid]
    ad = bytes(header) + bytes([sec])
    for c in window.candidates(seq):
        if not window.fresh(c):
            continue
        n = nonce(ep.epoch, lcid, c)
        try:
            if sec & SEC_ENCRYPTED:
                plain = crypto.aead_open(key, n, ad, payload, tag)
            else:
                crypto.aead_open(key, n, ad + payload, b"", tag)
                plain = payload
        except AuthError:
            continue
        window.accept(c)
        return plain
    raise AuthError("no counter authenticates")


class _Session:
    def __init__(self, k_init_to_resp: bytes, k_resp_to_init: bytes, role: str,
                 start_ms: int) -> None:
        self.start_ms = start_ms
        if role == INITIATOR:
            self.tx, self.rx = _TxChain(k_init_to_resp), _RxChain(k_resp_to_init)
        else:
            self.tx, self.rx = _TxChain(k_resp_to_init), _RxChain(k_init_to_resp)

    def age(self, now_ms: int) -> int:
        return now_ms - self.start_ms

    def usable(self, now_ms: int) -> bool:
        return 0 <= self.age(now_ms) < SESSION_MAX_MS

    def expected_epoch(self, now_ms: int) -> int:
        return max(0, self.age(now_ms)) // EPOCH_MS


def _resolve_epoch(bits: int, expected: int) -> int | None:
    d = (bits - expected) & 3
    if d == 2:
        return None
    if d == 3:
        d = -1
    e = expected + d
    return e if e >= 0 else None


class SecureLink:
    """One end of an SZ-Link security association.

    The initiator is the ground station; the responder is the vehicle.
    """

    def __init__(self, role: str, static_private: bytes, peer_public: bytes) -> None:
        if role not in (INITIATOR, RESPONDER):
            raise ValueError("role must be INITIATOR or RESPONDER")
        self.role = role
        self.static_private = static_private
        self.peer_public = peer_public
        self.cur: _Session | None = None
        self.pending: _Session | None = None   # responder: awaiting key confirmation
        self.prev: _Session | None = None
        self.prev_until_ms = 0
        self._hs: crypto.HandshakeInitiator | None = None
        self._hs_sent_ms = 0
        self._last_kex_timestamp = -1   # responder: newest accepted KEX_INIT
        self._last_rx_ms: int | None = None
        self.stats = {"auth_fail": 0, "rekeys": 0, "kex_replay": 0}

    @classmethod
    def from_identity(cls, role: str, identity_seed: bytes, peer_identity: bytes) -> "SecureLink":
        """Set up from this end's Ed25519 identity seed and the paired peer's
        identity public key (see ``crypto.identity_*``)."""
        return cls(role, crypto.identity_to_x25519_private(identity_seed),
                   crypto.identity_to_x25519_public(peer_identity))

    # --- handshake ------------------------------------------------------------

    def needs_kex(self, now_ms: int) -> bool:
        """Initiator: True when a KEX_INIT should be sent now."""
        if self.role != INITIATOR:
            return False
        if self._hs is not None and now_ms - self._hs_sent_ms < KEX_RETRY_MS:
            return False
        if self.cur is None or self.cur.age(now_ms) >= REKEY_MS:
            return True
        # the vehicle rebooted or lost the session: nothing authenticates any more
        last = self._last_rx_ms if self._last_rx_ms is not None else self.cur.start_ms
        return now_ms - max(last, self.cur.start_ms) >= RX_IDLE_REKEY_MS

    def kex_init(self, now_ms: int, ephemeral_private: bytes | None = None,
                 timestamp_us: int | None = None) -> bytes:
        """Initiator: start a handshake; returns the KEX_INIT payload.

        ``timestamp_us`` must increase with every call, also across restarts
        of the ground station (default: wall-clock microseconds).
        """
        if timestamp_us is None:
            timestamp_us = time.time_ns() // 1000
        self._hs = crypto.HandshakeInitiator(self.static_private, self.peer_public,
                                             ephemeral_private)
        self._hs_sent_ms = now_ms
        return self._hs.write_init(timestamp_us)

    def handle_kex_resp(self, msg: bytes, now_ms: int) -> bool:
        if self.role != INITIATOR or self._hs is None:
            return False
        try:
            k1, k2 = self._hs.read_resp(msg)
        except AuthError:
            self.stats["auth_fail"] += 1
            return False
        self._hs = None
        self._retire_current(now_ms)
        self.cur = _Session(k1, k2, INITIATOR, now_ms)
        self.stats["rekeys"] += 1
        return True

    def handle_kex_init(self, msg: bytes, now_ms: int,
                        ephemeral_private: bytes | None = None) -> bytes | None:
        """Responder: returns the KEX_RESP payload, or None if rejected."""
        if self.role != RESPONDER:
            return None
        try:
            resp, k1, k2, timestamp = crypto.HandshakeResponder(
                self.static_private, self.peer_public).respond(msg, ephemeral_private)
        except AuthError:
            self.stats["auth_fail"] += 1
            return None
        if timestamp <= self._last_kex_timestamp:
            self.stats["kex_replay"] += 1
            return None
        self._last_kex_timestamp = timestamp
        self.pending = _Session(k1, k2, RESPONDER, now_ms)
        return resp

    def _retire_current(self, now_ms: int) -> None:
        if self.cur is not None:
            self.prev = self.cur
            self.prev_until_ms = now_ms + PREV_SESSION_GRACE_MS

    # --- frames ---------------------------------------------------------------

    def has_session(self, now_ms: int) -> bool:
        return self._tx_session(now_ms) is not None

    def _tx_session(self, now_ms: int) -> _Session | None:
        for s in (self.cur, self.pending):
            if s is not None and s.usable(now_ms):
                return s
        return None

    def seal(self, header: bytearray, payload: bytes, mode: int, now_ms: int,
             flags: int = 0) -> tuple[int, bytes, bytes]:
        """Protect one frame.

        ``header`` is the 9-byte frame header (STX..MSGID); its SEQ byte is
        overwritten with the low byte of the frame counter. ``mode`` is
        MODE_ENCRYPT or MODE_SIGN; ``flags`` adds other SEC bits (SEC_FEC),
        which are authenticated too. Returns ``(sec, payload, tag)``.
        """
        if mode not in (MODE_ENCRYPT, MODE_SIGN):
            raise ValueError("bad mode")
        lcid = header[2]
        if lcid >= NUM_LCID:
            raise ValueError("unknown LCID")
        s = self._tx_session(now_ms)
        if s is None:
            raise AuthError("no session")
        epoch = s.expected_epoch(now_ms)
        if epoch > s.tx.epoch:
            s.tx.advance_to(epoch)
        ctr = s.tx.counters[lcid]
        if ctr >= 1 << 32:
            raise AuthError("counter exhausted")
        s.tx.counters[lcid] = ctr + 1
        header[3] = ctr & 0xFF
        sec = mode | (flags & SEC_FEC) | ((s.tx.epoch & 3) << SEC_EPOCH_SHIFT)
        ad = bytes(header) + bytes([sec])
        n = nonce(s.tx.epoch, lcid, ctr)
        key = s.tx.keys[lcid]
        if mode == MODE_ENCRYPT:
            ct, tag = crypto.aead_seal(key, n, ad, payload, tag_len(lcid))
            return sec, ct, tag
        _, tag = crypto.aead_seal(key, n, ad + payload, b"", tag_len(lcid))
        return sec, bytes(payload), tag

    def open(self, header: bytes, payload: bytes, sec: int, tag: bytes, now_ms: int) -> bytes:
        """Verify (and decrypt) one received frame, or raise AuthError."""
        if not sec & (SEC_ENCRYPTED | SEC_SIGNED) or header[2] >= NUM_LCID:
            raise AuthError("frame is not protected")
        if len(tag) != tag_len(header[2]):
            raise AuthError("bad tag length")
        bits = (sec & SEC_EPOCH_MASK) >> SEC_EPOCH_SHIFT
        candidates = [("cur", self.cur), ("pending", self.pending)]
        if self.prev is not None and now_ms < self.prev_until_ms:
            candidates.append(("prev", self.prev))
        for name, s in candidates:
            if s is None or not s.usable(now_ms):
                continue
            epoch = _resolve_epoch(bits, s.expected_epoch(now_ms))
            if epoch is None:
                continue
            try:
                plain = s.rx.open(header, payload, sec, tag, epoch)
            except AuthError:
                continue
            self._last_rx_ms = now_ms
            if name == "pending":
                self._retire_current(now_ms)
                self.cur, self.pending = s, None
                self.stats["rekeys"] += 1
            return plain
        self.stats["auth_fail"] += 1
        raise AuthError("frame does not authenticate")
