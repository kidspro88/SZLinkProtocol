"""Tests for szlink.session (key ratchet, rekey, replay) and szlink.crypto."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from szlink import crypto  # noqa: E402
from szlink.session import (  # noqa: E402
    EPOCH_MS,
    INITIATOR,
    MODE_ENCRYPT,
    MODE_SIGN,
    PREV_SESSION_GRACE_MS,
    REKEY_MS,
    RESPONDER,
    SEC_ENCRYPTED,
    SEC_EPOCH_MASK,
    SEC_SIGNED,
    SESSION_MAX_MS,
    AuthError,
    SecureLink,
    tag_len,
)

GCS_PRIV = bytes(range(1, 33))
VEH_PRIV = bytes(range(101, 133))


def header(lcid=1, length=4, msgid=0):
    return bytearray([0xFD, length, lcid, 0, 1, 1, msgid & 0xFF, msgid >> 8 & 0xFF, msgid >> 16])


def pair(now=0):
    gcs = SecureLink(INITIATOR, GCS_PRIV, crypto.x25519_public(VEH_PRIV))
    veh = SecureLink(RESPONDER, VEH_PRIV, crypto.x25519_public(GCS_PRIV))
    resp = veh.handle_kex_init(gcs.kex_init(now, timestamp_us=1000 + now), now)
    assert resp is not None
    assert gcs.handle_kex_resp(resp, now)
    assert veh.cur is None and veh.pending is not None
    send(gcs, veh, now, payload=b"conf")  # key confirmation promotes the session
    assert veh.cur is not None and veh.pending is None
    return gcs, veh


def send(tx, rx, now, lcid=1, payload=b"\x01\x02\x03\x04", mode=MODE_ENCRYPT, rx_now=None):
    h = header(lcid, len(payload))
    sec, ct, tag = tx.seal(h, payload, mode, now)
    return rx.open(bytes(h), ct, sec, tag, now if rx_now is None else rx_now)


class CryptoTest(unittest.TestCase):
    def test_rfc8439_aead_vector(self):
        # RFC 8439 section 2.8.2
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        ad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
              b"for the future, sunscreen would be it.")
        ct, tag = crypto.aead_seal(key, nonce, ad, pt)
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(ct[:16].hex(), "d31a8d34648e60db7b86afbc53ef7ec2")
        self.assertEqual(crypto.aead_open(key, nonce, ad, ct, tag), pt)
        self.assertEqual(crypto.aead_open(key, nonce, ad, ct, tag[:8]), pt)
        with self.assertRaises(AuthError):
            crypto.aead_open(key, nonce, ad, ct[:-1] + b"\x00", tag[:8])

    def test_hmac_blake2b_matches_rfc2104(self):
        import hashlib
        key, msg = b"k" * 200, b"message"
        k = hashlib.blake2b(key).digest().ljust(128, b"\0")
        inner = hashlib.blake2b(bytes(x ^ 0x36 for x in k) + msg).digest()
        outer = hashlib.blake2b(bytes(x ^ 0x5C for x in k) + inner).digest()
        self.assertEqual(crypto.hmac_blake2b(key, msg), outer)

    def test_handshake_rejects_unpaired_initiator(self):
        stranger = SecureLink(INITIATOR, bytes(range(50, 82)), crypto.x25519_public(VEH_PRIV))
        veh = SecureLink(RESPONDER, VEH_PRIV, crypto.x25519_public(GCS_PRIV))
        self.assertIsNone(veh.handle_kex_init(stranger.kex_init(0, timestamp_us=1), 0))
        self.assertIsNone(veh.pending)

    def test_handshake_rejects_tampered_messages(self):
        gcs = SecureLink(INITIATOR, GCS_PRIV, crypto.x25519_public(VEH_PRIV))
        veh = SecureLink(RESPONDER, VEH_PRIV, crypto.x25519_public(GCS_PRIV))
        msg = bytearray(gcs.kex_init(0, timestamp_us=1))
        msg[40] ^= 1
        self.assertIsNone(veh.handle_kex_init(bytes(msg), 0))
        resp = bytearray(veh.handle_kex_init(gcs.kex_init(0, timestamp_us=2), 0))
        resp[-1] ^= 1
        self.assertFalse(gcs.handle_kex_resp(bytes(resp), 0))


class SessionTest(unittest.TestCase):
    def test_roundtrip_all_channels_and_modes(self):
        gcs, veh = pair()
        for lcid in range(3):
            for mode in (MODE_ENCRYPT, MODE_SIGN):
                payload = bytes(range(lcid, lcid + 20))
                h = header(lcid, len(payload))
                sec, body, tag = gcs.seal(h, payload, mode, 10)
                self.assertEqual(len(tag), tag_len(lcid))
                self.assertEqual(sec & (SEC_ENCRYPTED | SEC_SIGNED), mode)
                if mode == MODE_SIGN:
                    self.assertEqual(body, payload)
                else:
                    self.assertNotEqual(body, payload)
                self.assertEqual(veh.open(bytes(h), body, sec, tag, 10), payload)
                # and the other direction
                self.assertEqual(send(veh, gcs, 11, lcid, payload, mode), payload)
        self.assertEqual(tag_len(0), 8)

    def test_header_and_sec_are_authenticated(self):
        gcs, veh = pair()
        h = header()
        sec, ct, tag = gcs.seal(h, b"abcd", MODE_ENCRYPT, 0)
        for i in (1, 2, 4, 5, 6):
            bad = bytearray(h)
            bad[i] ^= 1
            with self.assertRaises(AuthError):
                veh.open(bytes(bad), ct, sec, tag, 0)
        with self.assertRaises(AuthError):
            veh.open(bytes(h), ct, sec | 0x08, tag, 0)
        # signed-only: payload is authenticated
        h = header()
        sec, body, tag = gcs.seal(h, b"abcd", MODE_SIGN, 0)
        with self.assertRaises(AuthError):
            veh.open(bytes(h), b"abce", sec, tag, 0)
        self.assertEqual(veh.open(bytes(h), body, sec, tag, 0), b"abcd")

    def test_replay_rejected_reorder_accepted(self):
        gcs, veh = pair()
        frames = []
        for i in range(10):
            h = header()
            frames.append((h,) + gcs.seal(h, bytes([i]) * 4, MODE_ENCRYPT, 0))
        order = [0, 2, 1, 5, 3, 4, 9, 6, 8, 7]
        for i in order:
            h, sec, ct, tag = frames[i]
            self.assertEqual(veh.open(bytes(h), ct, sec, tag, 0), bytes([i]) * 4)
        for i in order:
            h, sec, ct, tag = frames[i]
            with self.assertRaises(AuthError):
                veh.open(bytes(h), ct, sec, tag, 0)

    def test_seq_carries_counter_and_survives_long_loss(self):
        gcs, veh = pair()
        for i in range(300):
            h = header(0)
            sec, ct, tag = gcs.seal(h, b"rc", MODE_ENCRYPT, 0)
            self.assertEqual(h[3], i & 0xFF)
            if i < 3 or i > 290:  # lose 288 frames in a row (> 256)
                self.assertEqual(veh.open(bytes(h), ct, sec, tag, 0), b"rc")

    def test_key_ratchets_every_epoch_without_traffic(self):
        gcs, veh = pair()
        seen = set()
        for epoch in range(0, 12):
            now = epoch * EPOCH_MS + 100
            h = header()
            sec, ct, tag = gcs.seal(h, b"tele", MODE_ENCRYPT, now)
            self.assertEqual((sec & SEC_EPOCH_MASK) >> 1, epoch & 3)
            seen.add(ct)
            # receiver also skips epochs it never heard (only every 3rd sent)
            if epoch % 3 == 0:
                self.assertEqual(veh.open(bytes(h), ct, sec, tag, now), b"tele")
        self.assertEqual(len(seen), 12)  # same plaintext, different key/nonce

    def test_epoch_boundary_clock_skew_and_late_frames(self):
        gcs, veh = pair()
        # sender just before the boundary, receiver just after
        self.assertEqual(send(gcs, veh, EPOCH_MS - 1, rx_now=EPOCH_MS + 50), b"\x01\x02\x03\x04")
        # sender after the boundary, receiver before
        self.assertEqual(send(gcs, veh, 2 * EPOCH_MS + 5, rx_now=2 * EPOCH_MS - 50),
                         b"\x01\x02\x03\x04")
        # a frame of the previous epoch arriving late is still accepted
        h = header()
        sec, ct, tag = gcs.seal(h, b"late", MODE_ENCRYPT, 2 * EPOCH_MS + 10)
        send(gcs, veh, 3 * EPOCH_MS + 10)
        self.assertEqual(veh.open(bytes(h), ct, sec, tag, 3 * EPOCH_MS + 20), b"late")

    def test_old_epoch_keys_are_forgotten(self):
        gcs, veh = pair()
        h = header()
        sec, ct, tag = gcs.seal(h, b"old!", MODE_ENCRYPT, 10)
        send(gcs, veh, 3 * EPOCH_MS)
        with self.assertRaises(AuthError):
            veh.open(bytes(h), ct, sec, tag, 3 * EPOCH_MS)

    def test_rekey_with_key_confirmation_and_grace(self):
        gcs, veh = pair()
        now = REKEY_MS
        self.assertTrue(gcs.needs_kex(now))
        old = gcs.cur
        resp = veh.handle_kex_init(gcs.kex_init(now, timestamp_us=10**9), now)
        self.assertFalse(gcs.needs_kex(now + 10))  # retry timer
        # vehicle keeps using the old session until the GCS proves the new one
        self.assertIsNotNone(veh.pending)
        h = header()
        sec, ct, tag = veh.seal(h, b"pre!", MODE_ENCRYPT, now)
        h2 = header()
        late = veh.seal(h2, b"pre2", MODE_ENCRYPT, now)
        self.assertTrue(gcs.handle_kex_resp(resp, now + 20))
        self.assertIsNot(gcs.cur, old)
        self.assertEqual(gcs.open(bytes(h), ct, sec, tag, now + 30), b"pre!")  # grace
        self.assertEqual(send(gcs, veh, now + 40), b"\x01\x02\x03\x04")
        self.assertIsNone(veh.pending)  # promoted
        self.assertEqual(send(veh, gcs, now + 50), b"\x01\x02\x03\x04")
        # the old session is kept for RX only during the grace period
        with self.assertRaises(AuthError):
            gcs.open(bytes(h2), late[1], late[0], late[2], now + 20 + PREV_SESSION_GRACE_MS)
        self.assertFalse(gcs.needs_kex(now + 100))
        self.assertEqual(gcs.prev, old)
        self.assertGreater(gcs.prev_until_ms, now)
        self.assertLessEqual(gcs.prev_until_ms, now + 20 + PREV_SESSION_GRACE_MS)

    def test_replayed_kex_init_is_rejected(self):
        gcs = SecureLink(INITIATOR, GCS_PRIV, crypto.x25519_public(VEH_PRIV))
        veh = SecureLink(RESPONDER, VEH_PRIV, crypto.x25519_public(GCS_PRIV))
        old = gcs.kex_init(0, timestamp_us=100)       # recorded by an attacker
        current = gcs.kex_init(1, timestamp_us=200)
        resp = veh.handle_kex_init(current, 2)
        self.assertTrue(gcs.handle_kex_resp(resp, 3))
        # replays (before and after key confirmation) must not replace the session
        self.assertIsNone(veh.handle_kex_init(old, 4))
        self.assertIsNone(veh.handle_kex_init(current, 5))
        self.assertEqual(veh.stats["kex_replay"], 2)
        self.assertIsNone(veh.handle_kex_init(b"\x00" * 10, 6))
        self.assertEqual(send(gcs, veh, 9), b"\x01\x02\x03\x04")
        self.assertEqual(send(veh, gcs, 9), b"\x01\x02\x03\x04")

    def test_initiator_rekeys_when_nothing_authenticates(self):
        gcs, veh = pair()
        self.assertFalse(gcs.needs_kex(4000))
        send(veh, gcs, 4000)
        self.assertFalse(gcs.needs_kex(8999))
        self.assertTrue(gcs.needs_kex(9000))  # e.g. the vehicle rebooted

    def test_session_expires(self):
        gcs, veh = pair()
        self.assertTrue(veh.has_session(SESSION_MAX_MS - 1))
        self.assertFalse(veh.has_session(SESSION_MAX_MS))
        with self.assertRaises(AuthError):
            send(gcs, veh, SESSION_MAX_MS - 1, rx_now=SESSION_MAX_MS + 1)

    def test_unprotected_frame_rejected(self):
        gcs, veh = pair()
        with self.assertRaises(AuthError):
            veh.open(bytes(header()), b"abcd", 0, b"", 0)


if __name__ == "__main__":
    unittest.main()
