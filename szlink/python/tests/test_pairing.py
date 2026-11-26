import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from szlink import crypto, pairing  # noqa: E402
from szlink.frame import FrameCodec  # noqa: E402
from szlink.session import INITIATOR, RESPONDER, SEC_ENCRYPTED, SecureLink  # noqa: E402


def msg_info(msgid):
    return {0: (50, 9), 1: (124, 31)}.get(msgid)


class IdentityTest(unittest.TestCase):
    def test_sign_verify(self):
        ident = pairing.Identity.generate()
        sig = crypto.identity_sign(ident.seed, b"firmware")
        self.assertTrue(crypto.identity_verify(ident.public, b"firmware", sig))
        self.assertFalse(crypto.identity_verify(ident.public, b"firmwarf", sig))
        other = pairing.Identity.generate()
        self.assertFalse(crypto.identity_verify(other.public, b"firmware", sig))

    def test_x25519_conversion_agrees(self):
        ident = pairing.Identity.generate()
        self.assertEqual(crypto.x25519_public(crypto.identity_to_x25519_private(ident.seed)),
                         crypto.identity_to_x25519_public(ident.public))

    def test_file_roundtrip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "gcs.key")
            ident = pairing.Identity.generate()
            ident.save(path)
            self.assertEqual(pairing.Identity.load(path), ident)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                pairing.Identity.generate().save(path)

    def test_fingerprint_format(self):
        fp = crypto.fingerprint(bytes(32))
        self.assertRegex(fp, r"^[0-9A-F]{4}(-[0-9A-F]{4}){3}$")


class PairingTest(unittest.TestCase):
    def test_pair_then_link(self):
        gcs, veh = pairing.Identity.generate(), pairing.Identity.generate()
        req = pairing.pair_request(gcs, 1, 1)
        self.assertEqual(len(req), 98)
        gcs_pub = pairing.parse_pair_request(req)
        self.assertEqual(gcs_pub, gcs.public)
        resp = pairing.pair_response(veh, gcs_pub, 255, 190)
        self.assertEqual(len(resp), 99)
        result, veh_pub = pairing.parse_pair_response(resp, gcs.public)
        self.assertEqual((result, veh_pub), (pairing.PAIR_ACCEPTED, veh.public))

        g = SecureLink.from_identity(INITIATOR, gcs.seed, veh_pub)
        v = SecureLink.from_identity(RESPONDER, veh.seed, gcs_pub)
        init = g.kex_init(0)
        g.handle_kex_resp(v.handle_kex_init(init, 0), 0)
        gc, vc = FrameCodec(msg_info, g), FrameCodec(msg_info, v)
        wire = gc.encode(0, bytes(9), 255, 190, 1, mode=SEC_ENCRYPTED, now_ms=10)
        frames = vc.parse(wire, 10)
        self.assertEqual(len(frames), 1)
        self.assertTrue(frames[0].authenticated)

    def test_stranger_cannot_use_link(self):
        gcs, veh, other = (pairing.Identity.generate() for _ in range(3))
        g = SecureLink.from_identity(INITIATOR, other.seed, veh.public)
        v = SecureLink.from_identity(RESPONDER, veh.seed, gcs.public)
        self.assertIsNone(v.handle_kex_init(g.kex_init(0), 0))
        self.assertEqual(v.stats["auth_fail"], 1)

    def test_tampered_messages(self):
        gcs, veh = pairing.Identity.generate(), pairing.Identity.generate()
        req = bytearray(pairing.pair_request(gcs, 1, 1))
        req[3] ^= 1   # key no longer matches the signature
        self.assertIsNone(pairing.parse_pair_request(bytes(req)))
        resp = bytearray(pairing.pair_response(veh, gcs.public, 255, 190))
        resp[40] ^= 1
        self.assertEqual(pairing.parse_pair_response(bytes(resp), gcs.public)[0],
                         pairing.PAIR_BAD_SIGNATURE)
        # a response signed for another ground station is refused
        resp = pairing.pair_response(veh, pairing.Identity.generate().public, 255, 190)
        self.assertEqual(pairing.parse_pair_response(resp, gcs.public)[0],
                         pairing.PAIR_BAD_SIGNATURE)
        # a refusal carries no key
        resp = pairing.pair_response(veh, gcs.public, 255, 190, pairing.PAIR_ARMED)
        self.assertEqual(pairing.parse_pair_response(resp, gcs.public), (pairing.PAIR_ARMED, None))


if __name__ == "__main__":
    unittest.main()
