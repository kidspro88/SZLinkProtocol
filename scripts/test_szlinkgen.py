"""Unit tests for scripts/szlinkgen.py (run: python -m unittest scripts/test_szlinkgen.py)."""

import contextlib
import io
import os
import shutil
import subprocess
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

    def test_accepts_directory_holding_only_empty_subdirectories(self):
        # Build tools (e.g. Ninja) create the parent directory of an OUTPUT file
        # before running the generator.
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "spacezet", "deeper"))
            szlinkgen.check_output_dir(root)

    def test_refuses_directory_with_file_in_subdirectory(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "spacezet"))
            open(os.path.join(root, "spacezet", "mine.h"), "w").close()
            with self.assertRaises(szlinkgen.GenerateError):
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


class LanguageTest(unittest.TestCase):
    def _capture(self, argv):
        calls = []
        original = szlinkgen.run_mavgen
        szlinkgen.run_mavgen = (lambda dialect, output, lang, wire_protocol:
                                calls.append((lang, wire_protocol)))
        try:
            with tempfile.TemporaryDirectory() as root:
                rc = szlinkgen.main(["--output", os.path.join(root, "out")] + argv)
        finally:
            szlinkgen.run_mavgen = original
        self.assertEqual(rc, 0)
        return calls

    def test_defaults_are_c_and_wire_protocol_2(self):
        self.assertEqual(self._capture([]), [("C", "2.0")])

    def test_cpp11_language_is_passed_to_mavgen(self):
        self.assertEqual(self._capture(["--lang", "C++11"]), [("C++11", "2.0")])

    def test_wire_protocol_1_is_passed_to_mavgen(self):
        self.assertEqual(self._capture(["--wire-protocol", "1.0"]), [("C", "1.0")])

    def test_unsupported_wire_protocol_is_rejected(self):
        with self.assertRaises(SystemExit):
            szlinkgen.main(["--output", "unused", "--wire-protocol", "3.0"])

    def test_unsupported_language_is_rejected(self):
        with self.assertRaises(SystemExit):
            szlinkgen.main(["--output", "unused", "--lang", "Python"])

    def test_cpp11_generation_renames_namespace_and_headers(self):
        dialect = os.path.join(szlinkgen.REPO_ROOT, "message_definitions", "v1.0", "minimal.xml")
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "szlink")
            szlinkgen.generate(out, dialect, lang="C++11")
            hpp = os.path.join(out, "minimal", "minimal.hpp")
            self.assertTrue(os.path.isfile(hpp))
            # C++11 output also carries the C headers
            self.assertTrue(os.path.isfile(os.path.join(out, "minimal", "szlink.h")))
            with open(hpp, encoding="utf-8") as f:
                self.assertIn("namespace szlink", f.read())
            # szlink_frame.h is hand-written and names the MAVLink 2 standard on purpose.
            leftovers = [hit for hit in szlinkgen.find_leftovers(out)
                         if os.path.basename(hit).split(":")[0] != "szlink_frame.h"]
            self.assertEqual(leftovers, [])

    def test_cpp11_with_wire_protocol_1_is_rejected(self):
        # mavgen's C++11 generator only supports wire protocol 2.0
        with self.assertRaises(SystemExit) as ctx:
            szlinkgen.main(["--output", "unused", "--lang", "C++11", "--wire-protocol", "1.0"])
        self.assertEqual(ctx.exception.code, 2)


def _fake_mavgen(dialect, output, lang, wire_protocol):
    os.makedirs(os.path.join(output, "minimal"))
    with open(os.path.join(output, "minimal", "mavlink.h"), "w") as f:
        f.write("#define MAVLINK_VERSION 3\n")


def _c_compiler():
    """Return a C compiler command line, or None if none is available."""
    for name in ("cc", "gcc", "clang"):
        path = shutil.which(name)
        if path:
            return [path]
    try:
        import ziglang  # noqa: F401  (pip install ziglang)
    except ImportError:
        return None
    return [sys.executable, "-m", "ziglang", "cc"]


class FrameLayerTest(unittest.TestCase):
    def setUp(self):
        self._original = szlinkgen.run_mavgen
        szlinkgen.run_mavgen = _fake_mavgen

    def tearDown(self):
        szlinkgen.run_mavgen = self._original

    def test_wire_protocol_2_copies_the_whole_frame_layer(self):
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "szlink")
            szlinkgen.generate(out)
            for name in szlinkgen.FRAME_LAYER_FILES:
                self.assertTrue(os.path.isfile(os.path.join(out, name)), name)
            for name in ("szlink_frame.h", "szlink_ecc.h", "szlink_sec.h",
                         "monocypher.h", "monocypher.c"):
                self.assertIn(name, szlinkgen.FRAME_LAYER_FILES)

    def test_wire_protocol_1_skips_frame_layer_with_warning(self):
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "szlink")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = szlinkgen.main(["--output", out, "--wire-protocol", "1.0"])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(os.path.join(out, "minimal", "szlink.h")))
            for name in szlinkgen.FRAME_LAYER_FILES:
                self.assertFalse(os.path.exists(os.path.join(out, name)), name)
            self.assertIn("warning", err.getvalue())
            self.assertIn("2.0", err.getvalue())


class FrameLayerCompileTest(unittest.TestCase):
    """The generated output alone (no -I into the repo) is enough to build the frame layer."""

    def test_frame_layer_builds_from_output_directory(self):
        cc = _c_compiler()
        if cc is None:
            self.skipTest("no C compiler found")
        dialect = os.path.join(szlinkgen.REPO_ROOT, "message_definitions", "v1.0", "spacezet.xml")
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "include", "szlink")
            szlinkgen.generate(out, dialect)
            main_c = os.path.join(root, "main.c")
            with open(main_c, "w") as f:
                f.write("#define SZLINK_SEC_IMPLEMENTATION\n"
                        "#define SZLINK_ECC_IMPLEMENTATION\n"
                        "#include \"spacezet/szlink.h\"\n"
                        "#include \"szlink_frame.h\"\n"
                        "int main(void) {\n"
                        "    szlink_frame_parser_t p;\n"
                        "    szlink_frame_parser_init(&p);\n"
                        "    return 0;\n"
                        "}\n")
            exe = os.path.join(root, "main.exe")
            result = subprocess.run(
                cc + ["-std=c99", "-Wall", "-Werror", "-Wno-address-of-packed-member",
                      "-I", out, main_c, os.path.join(out, "monocypher.c"), "-o", exe],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
