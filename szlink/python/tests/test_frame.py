"""Tests for szlink.frame: framing, tags, FEC envelopes and stream parsing."""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from szlink import crypto  # noqa: E402
from szlink.frame import LCID_RC, LCID_TELEMETRY, LCID_VIDEO, FrameCodec, crc16  # noqa: E402
from szlink.session import (  # noqa: E402
    INITIATOR,
    RESPONDER,
    SEC_ENCRYPTED,
    SEC_FEC,
    SEC_SIGNED,
    SecureLink,
)

# msgid -> (crc_extra, max payload length), from the generated dialect
MSGS = {0: (50, 9), 54000: (58, 10), 54001: (141, 255)}
HEARTBEAT = bytes([0, 0, 0, 0, 2, 3, 0, 3, 3])
RC = bytes([1, 1, 0x10, 0x27, 0, 0, 0xF0, 0xD8, 0x88, 0x13])
VIDEO = bytes(range(255))


def codecs(fec=0):
    g_priv, v_priv = os.urandom(32), os.urandom(32)
    gcs = SecureLink(INITIATOR, g_priv, crypto.x25519_public(v_priv))
    veh = SecureLink(RESPONDER, v_priv, crypto.x25519_public(g_priv))
    gcs.handle_kex_resp(veh.handle_kex_init(gcs.kex_init(0, timestamp_us=1), 0), 0)
    return FrameCodec(MSGS.get, gcs, fec), FrameCodec(MSGS.get, veh, fec)


def corrupt(rng, buf, count):
    buf = bytearray(buf)
    for p in rng.sample(range(len(buf)), count):
        buf[p] ^= rng.randint(1, 255)
    return bytes(buf)


class FrameTest(unittest.TestCase):
    def test_crc_is_mcrf4xx(self):
        self.assertEqual(crc16(b"123456789"), 0x6F91)

    def test_plain_frame_layout(self):
        tx = FrameCodec(MSGS.get)
        f = tx.encode(0, HEARTBEAT, 1, 1, LCID_TELEMETRY, seq=7)
        self.assertEqual(f[:9], bytes([0xFD, 9, 1, 7, 1, 1, 0, 0, 0]))
        self.assertEqual(len(f), 9 + 9 + 1 + 2)
        self.assertEqual(f[18], 0)  # SEC
        frames = FrameCodec(MSGS.get).parse(f)
        self.assertEqual(len(frames), 1)
        self.assertFalse(frames[0].authenticated)
        self.assertEqual(frames[0].payload, HEARTBEAT)

    def test_protected_frames_roundtrip(self):
        gcs, veh = codecs()
        cases = [(54000, RC, LCID_RC, 8), (0, HEARTBEAT, LCID_TELEMETRY, 16),
                 (54001, VIDEO, LCID_VIDEO, 16)]
        for msgid, payload, lcid, tl in cases:
            for mode in (SEC_ENCRYPTED, SEC_SIGNED):
                f = gcs.encode(msgid, payload, 255, 190, lcid, mode=mode, now_ms=5)
                self.assertEqual(len(f), 9 + len(payload) + 1 + tl + 2)
                (got,) = veh.parse(f, 5)
                self.assertTrue(got.authenticated)
                self.assertEqual(got.payload, payload)
                self.assertEqual(got.sec & (SEC_ENCRYPTED | SEC_SIGNED), mode)
                if mode == SEC_ENCRYPTED:
                    self.assertNotIn(payload[2:8], f)

    def test_forged_or_replayed_frame_dropped(self):
        gcs, veh = codecs()
        f = gcs.encode(0, HEARTBEAT, 1, 1, LCID_TELEMETRY, mode=SEC_SIGNED)
        self.assertEqual(len(veh.parse(f)), 1)
        self.assertEqual(veh.parse(f), [])  # replay
        attacker = FrameCodec(MSGS.get, codecs()[0].link)
        self.assertEqual(veh.parse(attacker.encode(0, HEARTBEAT, 1, 1, 1, mode=SEC_SIGNED)), [])
        self.assertEqual(veh.stats["auth_fail"], 2)
        # a following good frame is still found
        self.assertEqual(len(veh.parse(gcs.encode(0, HEARTBEAT, 1, 1, 1, mode=SEC_SIGNED))), 1)

    def test_video_fec_corrects_errors(self):
        rng = random.Random(3)
        gcs, veh = codecs(fec=16)
        for mode in (0, SEC_ENCRYPTED):
            f = gcs.encode(54001, VIDEO, 1, 1, LCID_VIDEO, mode=mode)
            self.assertEqual(f[0], 0xEC)
            (got,) = veh.parse(corrupt(rng, f, 8))
            self.assertEqual(got.payload, VIDEO)
            self.assertTrue(got.fec)
            self.assertTrue(got.sec & SEC_FEC)
        self.assertGreater(veh.stats["fec_corrected"], 0)
        # other channels are not wrapped
        self.assertEqual(gcs.encode(0, HEARTBEAT, 1, 1, LCID_TELEMETRY)[0], 0xFD)

    def test_fec_flag_must_match_transport(self):
        plain = FrameCodec(MSGS.get)
        fec_rx = FrameCodec(MSGS.get, fec_nsym=8)
        # FEC bit set but sent bare: dropped
        f = bytearray(plain.encode(54001, b"\x01", 1, 1, LCID_VIDEO))
        f[10] = SEC_FEC
        crc = crc16(bytes([141]), crc16(bytes(f[1:11])))
        f[11], f[12] = crc & 0xFF, crc >> 8
        self.assertEqual(fec_rx.parse(bytes(f)), [])
        # without FEC configured, envelopes are ignored
        fec_tx = FrameCodec(MSGS.get, fec_nsym=8)
        self.assertEqual(plain.parse(fec_tx.encode(54001, b"\x01", 1, 1, LCID_VIDEO)), [])

    def test_stream_resync_mixed(self):
        rng = random.Random(4)
        gcs, veh = codecs(fec=8)
        stream = bytearray()
        sent = []
        for i in range(40):
            stream += bytes(rng.randrange(256) for _ in range(rng.randint(0, 5)))
            if i % 3 == 0:
                stream += gcs.encode(54001, VIDEO[i:], 1, 1, LCID_VIDEO, mode=SEC_ENCRYPTED)
                sent.append(VIDEO[i:])
            else:
                stream += gcs.encode(54000, RC, 1, 1, LCID_RC, mode=SEC_ENCRYPTED)
                sent.append(RC)
        got = []
        for i in range(0, len(stream), 37):
            got += [f.payload for f in veh.parse(bytes(stream[i:i + 37]))]
        self.assertEqual(got, sent)


if __name__ == "__main__":
    unittest.main()
