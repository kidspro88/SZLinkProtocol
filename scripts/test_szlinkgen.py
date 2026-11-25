"""Unit tests for scripts/szlinkgen.py (run: python -m unittest scripts/test_szlinkgen.py)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import szlinkgen  # noqa: E402


class RenameTest(unittest.TestCase):
    def test_all_spellings(self):
        src = ("#include \"mavlink_types.h\"\n"
               "MAVLINK_HELPER void mavlink_finalize_message(mavlink_message_t *msg);\n"
               "// MAVLink protocol, Mavlink docs\n")
        out = szlinkgen.rename_text(src)
        self.assertEqual(out, ("#include \"szlink_types.h\"\n"
                               "SZLINK_HELPER void szlink_finalize_message(szlink_message_t *msg);\n"
                               "// SZLink protocol, Szlink docs\n"))

    def test_mav_enums_untouched(self):
        src = "MAV_TYPE_QUADROTOR _MAV_PAYLOAD(msg) MAV_CMD_NAV_TAKEOFF"
        self.assertEqual(szlinkgen.rename_text(src), src)

    def test_mav_enum_containing_mavlink_untouched(self):
        src = "MAV_PROTOCOL_CAPABILITY_MAVLINK2=4, /* uses MAVLINK2 */"
        self.assertEqual(szlinkgen.rename_text(src),
                         "MAV_PROTOCOL_CAPABILITY_MAVLINK2=4, /* uses SZLINK2 */")

    def test_mavlink_io_links_untouched(self):
        src = "see https://mavlink.io/en/guide/xml_schema.html#MAV_CMD for mavlink_msg"
        self.assertEqual(szlinkgen.rename_text(src),
                         "see https://mavlink.io/en/guide/xml_schema.html#MAV_CMD for szlink_msg")

    def test_find_leftovers_ignores_kept_tokens(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "x.h"), "w") as f:
                f.write("MAV_PROTOCOL_CAPABILITY_MAVLINK2 https://mavlink.io/x\n")
            self.assertEqual(szlinkgen.find_leftovers(root), [])

    def test_refuses_to_replace_foreign_directory(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "keep.txt"), "w") as f:
                f.write("mine\n")
            with self.assertRaises(szlinkgen.GenerateError):
                szlinkgen.check_output_dir(root)
            self.assertTrue(os.path.exists(os.path.join(root, "keep.txt")))

    def test_accepts_missing_empty_or_generated_directory(self):
        with tempfile.TemporaryDirectory() as root:
            szlinkgen.check_output_dir(os.path.join(root, "missing"))
            szlinkgen.check_output_dir(root)
            open(os.path.join(root, szlinkgen.MARKER), "w").close()
            open(os.path.join(root, "old.h"), "w").close()
            szlinkgen.check_output_dir(root)

    def test_rename_tree_renames_paths_and_contents(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            os.makedirs(os.path.join(src, "spacezet"))
            with open(os.path.join(src, "spacezet", "mavlink.h"), "w") as f:
                f.write("#include \"../mavlink_types.h\"\n")
            szlinkgen.rename_tree(src, dst)
            path = os.path.join(dst, "spacezet", "szlink.h")
            with open(path) as f:
                self.assertEqual(f.read(), "#include \"../szlink_types.h\"\n")
            self.assertEqual(szlinkgen.find_leftovers(dst), [])

    def test_find_leftovers_reports_names_and_lines(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "mavlink_x.h"), "w") as f:
                f.write("ok\nMAVLink here\n")
            hits = szlinkgen.find_leftovers(root)
            self.assertEqual(len(hits), 2)
            self.assertTrue(hits[1].endswith("mavlink_x.h:2"))


if __name__ == "__main__":
    unittest.main()
