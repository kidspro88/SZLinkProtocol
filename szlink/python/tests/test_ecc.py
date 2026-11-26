"""Tests for szlink.ecc (Python) and interop with szlink/c/szlink_ecc.h."""

import ctypes
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from szlink import ecc  # noqa: E402

C_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "c")

# A MAVLink 2 HEARTBEAT frame (sysid 1, compid 1).
HEARTBEAT_V2 = bytes.fromhex("fd09000000010100000000000000020300035185")

# Golden vector shared with szlink/c/test_szlink_ecc.c
GOLDEN_PAYLOAD = bytes(range(40))
GOLDEN_FRAME = bytes.fromhex(
    "ec2800840eb1ff"
    + GOLDEN_PAYLOAD.hex()
    + "5b715eaaf0b48913cbdd69e49af529dd"
)


def corrupt(rng, buf, count):
    buf = bytearray(buf)
    for p in rng.sample(range(len(buf)), min(count, len(buf))):
        buf[p] ^= rng.randint(1, 255)
    return bytes(buf)


class RSCodecTest(unittest.TestCase):
    def test_roundtrip_with_correctable_errors(self):
        rng = random.Random(1)
        for nsym in (2, 4, 16, 32, 64):
            codec = ecc.RSCodec(nsym)
            for _ in range(300):
                data = bytes(rng.randrange(256) for _ in range(rng.randint(1, 255 - nsym)))
                cw = codec.encode(data)
                self.assertEqual(len(cw), len(data) + nsym)
                nerr = rng.randint(0, nsym // 2)
                out, fixed = codec.decode(corrupt(rng, cw, nerr))
                self.assertEqual(out, data)
                self.assertEqual(fixed, min(nerr, len(cw)))

    def test_too_many_errors_rarely_miscorrects(self):
        rng = random.Random(2)
        codec = ecc.RSCodec(16)
        wrong = 0
        for _ in range(200):
            data = bytes(rng.randrange(256) for _ in range(200))
            try:
                out, _ = codec.decode(corrupt(rng, codec.encode(data), rng.randint(9, 16)))
            except ecc.ECCError:
                continue
            if out != data:
                wrong += 1
        self.assertLess(wrong, 5)

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            ecc.RSCodec(3)
        with self.assertRaises(ValueError):
            ecc.RSCodec(16).encode(bytes(240))


class FrameTest(unittest.TestCase):
    def test_golden_vector(self):
        self.assertEqual(ecc.SZLinkECC(16).encode(GOLDEN_PAYLOAD), GOLDEN_FRAME)

    def test_heartbeat_survives_errors(self):
        link = ecc.SZLinkECC()
        frame = link.encode(HEARTBEAT_V2)
        self.assertEqual(len(frame), link.encoded_length(len(HEARTBEAT_V2)))
        bad = bytearray(frame)
        bad[0] ^= 0xFF  # sync byte
        bad[10] ^= 0x01
        bad[20] ^= 0x80
        payload, fixed = link.decode(bytes(bad))
        self.assertEqual(payload, HEARTBEAT_V2)
        self.assertEqual(fixed, 3)

    def test_multi_block_payload(self):
        rng = random.Random(3)
        link = ecc.SZLinkECC(16)
        for length in (1, 238, 239, 240, 280, 600):
            payload = bytes(rng.randrange(256) for _ in range(length))
            frame = bytearray(link.encode(payload))
            frame[: ecc.HEADER_LEN] = corrupt(rng, frame[: ecc.HEADER_LEN], 2)
            pos = ecc.HEADER_LEN
            remaining = length
            while remaining:
                dlen = min(link.body.max_data, remaining)
                blk = pos + dlen + link.nsym
                frame[pos:blk] = corrupt(rng, frame[pos:blk], 8)
                pos, remaining = blk, remaining - dlen
            self.assertEqual(link.decode(bytes(frame))[0], payload)

    def test_stream_resync(self):
        rng = random.Random(4)
        tx = ecc.SZLinkECC()
        rx = ecc.SZLinkECC()
        payloads = [bytes(rng.randrange(256) for _ in range(rng.randint(1, 280))) for _ in range(20)]
        stream = bytearray(b"\x00\xec\x12garbage")
        for p in payloads:
            stream += corrupt(rng, tx.encode(p)[:7], 1) + corrupt(rng, tx.encode(p)[7:], 3)
            stream += bytes(rng.randrange(256) for _ in range(rng.randint(0, 5)))
        got = []
        for i in range(0, len(stream), 13):
            got += rx.feed(bytes(stream[i : i + 13]))
        self.assertEqual(got, payloads)
        self.assertEqual(rx.stats["frames"], len(payloads))

    def test_uncorrectable_raises(self):
        link = ecc.SZLinkECC(4)
        frame = bytearray(link.encode(b"hello world"))
        for p in range(8, 16):
            frame[p] ^= 0x55
        with self.assertRaises(ecc.ECCError):
            link.decode(bytes(frame))


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class CInteropTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        src = os.path.join(cls.tmp, "lib.c")
        with open(src, "w") as f:
            f.write('#define SZLINK_ECC_IMPLEMENTATION\n#include "szlink_ecc.h"\n')
        lib = os.path.join(cls.tmp, "libszlink_ecc.so")
        subprocess.check_call(["gcc", "-shared", "-fPIC", "-O2", "-I", C_DIR, src, "-o", lib])
        cls.lib = ctypes.CDLL(lib)
        u8p, sz = ctypes.c_char_p, ctypes.c_size_t
        cls.lib.szlink_ecc_encode.argtypes = [u8p, sz, ctypes.c_uint8, u8p, sz]
        cls.lib.szlink_ecc_decode.argtypes = [
            u8p, sz, ctypes.c_uint8, u8p, sz, ctypes.POINTER(ctypes.c_int)]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def c_encode(self, payload, nsym):
        out = ctypes.create_string_buffer(len(payload) * 2 + 300)
        n = self.lib.szlink_ecc_encode(payload, len(payload), nsym, out, len(out))
        self.assertGreater(n, 0)
        return out.raw[:n]

    def c_decode(self, frame, nsym):
        buf = ctypes.create_string_buffer(frame, len(frame))
        out = ctypes.create_string_buffer(len(frame))
        fixed = ctypes.c_int(-1)
        n = self.lib.szlink_ecc_decode(buf, len(frame), nsym, out, len(out), ctypes.byref(fixed))
        return n, out.raw[: max(n, 0)], fixed.value

    def test_python_and_c_agree(self):
        rng = random.Random(5)
        for nsym in (4, 16, 32):
            link = ecc.SZLinkECC(nsym)
            for _ in range(50):
                payload = bytes(rng.randrange(256) for _ in range(rng.randint(1, 600)))
                py_frame = link.encode(payload)
                self.assertEqual(self.c_encode(payload, nsym), py_frame)
                # 1 error in the header, nsym // 2 in the first body block.
                end = 7 + min(len(payload), 255 - nsym) + nsym
                bad = (corrupt(rng, py_frame[:7], 1)
                       + corrupt(rng, py_frame[7:end], nsym // 2)
                       + py_frame[end:])
                n, out, c_fixed = self.c_decode(bad, nsym)
                self.assertEqual(n, len(payload))
                self.assertEqual(out, payload)
                py_out, py_fixed = link.decode(bad)
                self.assertEqual(py_out, payload)
                self.assertEqual(c_fixed, py_fixed)


if __name__ == "__main__":
    unittest.main()
