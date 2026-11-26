"""SZ-Link frame codec (ground-station side reference implementation).

Wire format, byte-compatible with ``szlink/c/szlink_frame.h``::

    STX | LEN | LCID | SEQ | SYSID | COMPID | MSGID(3) | PAYLOAD | SEC | [TAG] | CRC(2)

* ``TAG`` (8 bytes on LCID RC, 16 otherwise) is present when SEC has the
  ENCRYPTED or SIGNED bit; LEN never counts it.
* CRC-16/MCRF4XX over LEN..TAG, then the message's CRC_EXTRA.
* With SEC_FEC set the whole frame is sent inside a Reed-Solomon envelope
  (``szlink.ecc``), which starts with 0xEC instead of 0xFD. Only video
  frames are sent this way.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from . import ecc
from .session import (
    SEC_ENCRYPTED,
    SEC_FEC,
    SEC_SIGNED,
    AuthError,
    SecureLink,
    tag_len,
)

__all__ = ["Frame", "FrameCodec", "crc16", "STX", "LCID_RC", "LCID_TELEMETRY", "LCID_VIDEO"]

STX = 0xFD
HEADER_LEN = 9
LCID_RC, LCID_TELEMETRY, LCID_VIDEO = 0, 1, 2
FEC_MAX_NSYM = 32
# largest frame (255-byte payload, 16-byte tag) and its FEC envelope, as in szlink_frame.h
FRAME_MAX_LEN = HEADER_LEN + 3 + 255 + 16
FEC_MAX_LEN = ecc.HEADER_LEN + FRAME_MAX_LEN + 2 * FEC_MAX_NSYM

MsgInfo = Callable[[int], Optional[tuple[int, int]]]  # msgid -> (crc_extra, max_len)


def crc16(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/MCRF4XX (MAVLink X.25)."""
    for b in data:
        tmp = (b ^ crc) & 0xFF
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


@dataclass
class Frame:
    lcid: int
    seq: int
    sysid: int
    compid: int
    msgid: int
    payload: bytes        # plaintext when ``authenticated``
    sec: int
    authenticated: bool   # True if the tag was verified by the SecureLink
    fec: bool = False     # arrived inside an FEC envelope


class FrameCodec:
    """Encode and parse SZ-Link frames for one link.

    ``msg_info(msgid)`` returns ``(crc_extra, max_payload_len)`` or None for
    unknown messages. ``link`` (optional) protects/verifies frames.
    ``fec_nsym`` > 0 sends video frames in an RS envelope with that many
    parity bytes per block and accepts envelopes on receive.
    """

    def __init__(self, msg_info: MsgInfo, link: SecureLink | None = None,
                 fec_nsym: int = 0) -> None:
        if fec_nsym and (fec_nsym < 2 or fec_nsym > FEC_MAX_NSYM or fec_nsym & 1):
            raise ValueError("fec_nsym must be 0 or an even number in 2..32")
        self.msg_info = msg_info
        self.link = link
        self.fec = ecc.SZLinkECC(fec_nsym) if fec_nsym else None
        self._buf = bytearray()
        self.stats = {"rx_ok": 0, "crc_errors": 0, "unknown_msgid": 0, "len_errors": 0,
                      "auth_fail": 0, "fec_fail": 0, "fec_corrected": 0}

    # --- transmit -------------------------------------------------------------

    def encode(self, msgid: int, payload: bytes, sysid: int, compid: int, lcid: int,
               seq: int = 0, mode: int = 0, now_ms: int = 0) -> bytes:
        """Build one frame. ``mode`` is 0, SEC_SIGNED or SEC_ENCRYPTED."""
        info = self.msg_info(msgid)
        if info is None:
            raise ValueError(f"unknown msgid {msgid}")
        crc_extra, max_len = info
        payload = bytes(payload)[:max_len]
        end = len(payload)
        while end > 1 and payload[end - 1] == 0:   # MAVLink 2 trailing-zero trimming
            end -= 1
        payload = payload[:end]
        header = bytearray([STX, len(payload), lcid, seq & 0xFF, sysid, compid,
                            msgid & 0xFF, (msgid >> 8) & 0xFF, (msgid >> 16) & 0xFF])
        use_fec = self.fec is not None and lcid == LCID_VIDEO
        flags = SEC_FEC if use_fec else 0
        tag = b""
        if mode:
            if self.link is None:
                raise AuthError("no SecureLink for a protected frame")
            sec, payload, tag = self.link.seal(header, payload, mode, now_ms, flags)
        else:
            sec = flags
        body = bytes(header) + payload + bytes([sec]) + tag
        crc = crc16(bytes([crc_extra]), crc16(body[1:]))
        frame = body + bytes([crc & 0xFF, crc >> 8])
        return self.fec.encode(frame) if use_fec else frame

    # --- receive --------------------------------------------------------------

    def parse(self, data: bytes, now_ms: int = 0) -> list[Frame]:
        """Feed received bytes; returns the complete, valid frames."""
        self._buf += data
        out: list[Frame] = []
        while self._buf:
            start = self._buf[0]
            if start == STX:
                need, frame = self._try_frame(self._buf, now_ms, False)
            elif start == ecc.MAGIC and self.fec is not None:
                need, frame = self._try_envelope(now_ms)
            else:
                del self._buf[0]
                continue
            if need > 0:
                break             # wait for more bytes
            if frame is None:
                if need < 0:
                    del self._buf[:-need]   # skip a whole valid frame we cannot use
                else:
                    del self._buf[0]        # resync
                continue
            del self._buf[:frame[1]]
            out.append(frame[0])
        return out

    def _try_envelope(self, now_ms: int):
        assert self.fec is not None
        if len(self._buf) < ecc.HEADER_LEN:
            return 1, None
        try:
            length, _ = self.fec._decode_header(bytes(self._buf[:ecc.HEADER_LEN]))
        except ecc.ECCError:
            return 0, None
        total = self.fec.encoded_length(length)
        if total > FEC_MAX_LEN:
            return 0, None  # the header RS code is unkeyed: do not wait for a forged length
        if len(self._buf) < total:
            return 1, None
        try:
            inner, fixed = self.fec.decode(bytes(self._buf[:total]))
        except ecc.ECCError:
            self.stats["fec_fail"] += 1
            return 0, None
        need, frame = self._try_frame(bytearray(inner), now_ms, True)
        if frame is None or frame[1] != len(inner):
            return (-total if need < 0 else 0), None
        self.stats["fec_corrected"] += fixed
        return 0, (frame[0], total)

    def _try_frame(self, b: bytearray, now_ms: int, in_envelope: bool):
        """Returns (need, None) to wait (need>0), resync (0) or skip (-n);
        or (0, (Frame, length))."""
        if len(b) < 2:
            return 1, None
        length = b[1]
        if len(b) < HEADER_LEN + length + 1:
            return 1, None
        sec = b[HEADER_LEN + length]
        lcid = b[2]
        tl = tag_len(lcid) if sec & (SEC_ENCRYPTED | SEC_SIGNED) else 0
        total = HEADER_LEN + length + 1 + tl + 2
        if len(b) < total:
            return 1, None
        msgid = b[6] | (b[7] << 8) | (b[8] << 16)
        info = self.msg_info(msgid)
        if info is None:
            self.stats["unknown_msgid"] += 1
            return 0, None
        crc_extra, max_len = info
        if length > max_len:
            self.stats["len_errors"] += 1
            return 0, None
        crc = crc16(bytes([crc_extra]), crc16(bytes(b[1:total - 2])))
        if crc != (b[total - 2] | (b[total - 1] << 8)):
            self.stats["crc_errors"] += 1
            return 0, None
        if bool(sec & SEC_FEC) != in_envelope:
            # FEC flag must match how the frame arrived; it is authenticated
            self.stats["len_errors"] += 1
            return -total, None
        header = bytes(b[:HEADER_LEN])
        payload = bytes(b[HEADER_LEN:HEADER_LEN + length])
        authenticated = False
        if tl:
            if self.link is None:
                self.stats["auth_fail"] += 1
                return -total, None
            tag = bytes(b[HEADER_LEN + length + 1:HEADER_LEN + length + 1 + tl])
            try:
                payload = self.link.open(header, payload, sec, tag, now_ms)
            except AuthError:
                self.stats["auth_fail"] += 1
                return -total, None
            authenticated = True
        self.stats["rx_ok"] += 1
        return 0, (Frame(lcid, b[3], b[4], b[5], msgid, payload, sec, authenticated,
                         in_envelope), total)
