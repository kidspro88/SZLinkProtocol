import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "szlink", "python"))

import szfw  # noqa: E402
import szfw_sim  # noqa: E402
from szlink.pairing import Identity  # noqa: E402


class ImageTest(unittest.TestCase):
    def test_sign_and_verify(self):
        key = Identity.generate()
        body = os.urandom(3000)
        image = szfw.sign_image(key.seed, body, board_id=3, fw_version=5, key_id=0)
        self.assertEqual(len(image), szfw.HEADER_LEN + 3000)
        self.assertEqual(szfw.verify_image(image, [key.public]), szfw.STATUS_OK)
        bad = bytearray(image)
        bad[-1] ^= 1
        self.assertEqual(szfw.verify_image(bytes(bad), [key.public]), szfw.STATUS_BAD_SIGNATURE)
        self.assertEqual(szfw.verify_image(image, [Identity.generate().public]), szfw.STATUS_BAD_SIGNATURE)
        self.assertEqual(szfw.verify_image(image, []), szfw.STATUS_UNKNOWN_KEY)
        self.assertEqual(szfw.verify_image(image[:-1], [key.public]), szfw.STATUS_INCOMPLETE)
        self.assertEqual(szfw.verify_image(b"nope" + image[4:], [key.public]), szfw.STATUS_BAD_HEADER)


class SimUpdateTest(unittest.TestCase):
    """the C update code (via ctypes) accepts Python-signed images"""

    @classmethod
    def setUpClass(cls):
        cls.lib = szfw_sim.build()

    def update(self, esc, image):
        st, nxt, size = esc.boot_command(szfw.COMMAND_BEGIN, image[:szfw.HEADER_LEN])
        if st != szfw.STATUS_OK:
            return st
        body = image[szfw.HEADER_LEN:]
        while nxt < size:
            st, nxt = esc.chunk(nxt, body[nxt:nxt + szfw.CHUNK_MAX])
            if st != szfw.STATUS_OK:
                return st
        return esc.boot_command(szfw.COMMAND_COMMIT, b"")[0]

    def test_update(self):
        key = Identity.generate()
        body = os.urandom(10000)
        esc = szfw_sim.SimFlash(board_id=3, keys=[key.public], installed_version=1, lib_path=self.lib)
        image = szfw.sign_image(key.seed, body, board_id=3, fw_version=2)
        self.assertEqual(self.update(esc, image), szfw.STATUS_OK)
        self.assertEqual((esc.installs, esc.installed_version, esc.app()), (1, 2, body))
        # older firmware, other board, unknown signer: refused
        self.assertEqual(self.update(esc, szfw.sign_image(key.seed, body, 3, 1)), szfw.STATUS_DOWNGRADE)
        self.assertEqual(self.update(esc, szfw.sign_image(key.seed, body, 4, 3)), szfw.STATUS_WRONG_BOARD)
        other = Identity.generate()
        self.assertEqual(self.update(esc, szfw.sign_image(other.seed, body, 3, 3)), szfw.STATUS_BAD_SIGNATURE)
        self.assertEqual(esc.installs, 1)


if __name__ == "__main__":
    unittest.main()
