"""The C test vectors must match what the Python implementation produces."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import gen_c_vectors  # noqa: E402


class VectorsTest(unittest.TestCase):
    def test_checked_in_header_is_current(self):
        path = os.path.join(HERE, "..", "..", "c", "szlink_test_vectors.h")
        with open(path) as f:
            self.assertEqual(f.read(), gen_c_vectors.render(),
                             "regenerate with szlink/python/tools/gen_c_vectors.py")


if __name__ == "__main__":
    unittest.main()
