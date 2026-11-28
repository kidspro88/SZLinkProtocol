#!/usr/bin/env python3
"""Generate the SZ-Link C library.

Runs pymavlink's mavgen (C or C++11; wire protocol 2.0 by default) on a dialect, then renames every
``mavlink``/``MAVLINK``/``MAVLink`` identifier, file name and comment to
``szlink``/``SZLINK``/``SZLink`` and adds the SZ-Link frame layer
(``szlink_frame.h`` with ``szlink_ecc.h``, ``szlink_sec.h`` and Monocypher,
copied from ``szlink/c``). Build ``monocypher.c`` from the output directory
and define ``SZLINK_SEC_IMPLEMENTATION`` / ``SZLINK_ECC_IMPLEMENTATION`` in one
.c file. The frame layer needs wire protocol 2.0 and is left out for 1.0.

Usage::

    python3 scripts/szlinkgen.py --output build/szlink
    # then:  #include "spacezet/szlink.h"  and  #include "szlink_frame.h"
    python3 scripts/szlinkgen.py --lang C++11 --output build/szlink
    # also writes the C++11 headers:  #include "spacezet/spacezet.hpp"

``MAV_*`` enums (MAV_TYPE, MAV_CMD, MAV_PROTOCOL_CAPABILITY_MAVLINK2, ...) keep
their names: they are protocol values, not code, and keeping them lets SZ-Link
telemetry stay readable by standard MAVLink tooling. Links to mavlink.io are
kept as they are.

The output directory is replaced only if it is empty or was written by this
tool (it then holds a ``.szlinkgen`` marker file); anything else is refused.
"""

import argparse
import os
import re
import shutil
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DIALECT = os.path.join(REPO_ROOT, "message_definitions", "v1.0", "spacezet.xml")
FRAME_C_DIR = os.path.join(REPO_ROOT, "szlink", "c")
# Frame layer, copied flat into the output root (path relative to szlink/c).
# szlink_sec.h includes "monocypher.h", found next to it.
FRAME_LAYER_SOURCES = (
    "szlink_frame.h",
    "szlink_ecc.h",
    "szlink_sec.h",
    os.path.join("third_party", "monocypher", "monocypher.h"),
    os.path.join("third_party", "monocypher", "monocypher.c"),
)
FRAME_LAYER_FILES = tuple(os.path.basename(path) for path in FRAME_LAYER_SOURCES)
MARKER = ".szlinkgen"
# mavgen's C++11 generator also writes the C headers next to the *.hpp files.
LANGUAGES = ("C", "C++11")
DEFAULT_LANGUAGE = "C"
# The SZ-Link frame layer needs 2.0 payloads; 1.0 is kept for plain message headers.
WIRE_PROTOCOLS = ("1.0", "2.0")
DEFAULT_WIRE_PROTOCOL = "2.0"

_RENAMES = [
    (re.compile("MAVLINK"), "SZLINK"),
    (re.compile("MAVLink"), "SZLink"),
    (re.compile("Mavlink"), "Szlink"),
    (re.compile("mavlink"), "szlink"),
]

# Left alone by the rename: MAV_* protocol enum names and mavlink.io links.
_KEEP = re.compile(r"\bMAV_[A-Z0-9_]*|(?:https?://)?(?:www\.)?mavlink\.io\b[^\s\"')]*")

_LEFTOVER = re.compile("mavlink", re.IGNORECASE)


class GenerateError(Exception):
    """Generation failed; the message says why."""


def _rename_plain(text):
    for pattern, replacement in _RENAMES:
        text = pattern.sub(replacement, text)
    return text


def rename_text(text):
    """Rename every mavlink spelling in ``text`` to its szlink spelling,
    except inside MAV_* identifiers and mavlink.io links."""
    out = []
    pos = 0
    for keep in _KEEP.finditer(text):
        out.append(_rename_plain(text[pos:keep.start()]))
        out.append(keep.group(0))
        pos = keep.end()
    out.append(_rename_plain(text[pos:]))
    return "".join(out)


def find_leftovers(root):
    """Return ``path:line`` for every remaining mavlink spelling under ``root``
    that rename_text does not keep on purpose."""
    hits = []
    for dirpath, _, files in os.walk(root):
        for name in files:
            if name == MARKER:
                continue
            path = os.path.join(dirpath, name)
            if _LEFTOVER.search(name):
                hits.append(path)
            with open(path, encoding="utf-8", errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    if _LEFTOVER.search(_KEEP.sub("", line)):
                        hits.append(f"{path}:{lineno}")
    return hits


def rename_tree(src, dst):
    """Copy ``src`` to ``dst``, renaming file names and file contents.
    Line endings are kept as mavgen wrote them."""
    for dirpath, _, files in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        out_dir = os.path.join(dst, rename_text(rel)) if rel != "." else dst
        os.makedirs(out_dir, exist_ok=True)
        for name in files:
            with open(os.path.join(dirpath, name), encoding="utf-8", newline="") as f:
                text = f.read()
            with open(os.path.join(out_dir, rename_text(name)), "w", encoding="utf-8", newline="") as f:
                f.write(rename_text(text))


def run_mavgen(dialect, output, lang, wire_protocol):
    sys.path.insert(0, REPO_ROOT)  # use the pymavlink submodule
    from pymavlink.generator import mavgen

    opts = mavgen.Opts(output, wire_protocol=wire_protocol, language=lang, validate=True,
                       strict_units=True)
    if not mavgen.mavgen(opts, [dialect]):
        raise GenerateError(f"mavgen failed for {dialect}")


def check_output_dir(output):
    """Refuse to replace a directory this tool did not create."""
    if not os.path.exists(output):
        return
    if not os.path.isdir(output):
        raise GenerateError(f"{output} exists and is not a directory")
    # Empty subdirectories do not count: build tools such as Ninja create the
    # parent directory of an OUTPUT file before running the generator.
    has_files = any(files for _, _, files in os.walk(output))
    if has_files and not os.path.isfile(os.path.join(output, MARKER)):
        raise GenerateError(f"refusing to replace {output}: it is not empty and was not "
                            f"generated by szlinkgen (no {MARKER} file)")


def generate(output, dialect=DEFAULT_DIALECT, lang=DEFAULT_LANGUAGE,
             wire_protocol=DEFAULT_WIRE_PROTOCOL):
    """Generate into a staging directory next to ``output``, check it, and only
    then replace ``output``, so a failed run leaves the old output in place."""
    output = os.path.abspath(output)
    check_output_dir(output)
    parent = os.path.dirname(output)
    os.makedirs(parent, exist_ok=True)
    staged = tempfile.mkdtemp(prefix=".szlinkgen-", dir=parent)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            run_mavgen(dialect, tmp, lang, wire_protocol)
            rename_tree(tmp, staged)
        leftovers = find_leftovers(staged)
        if leftovers:
            raise GenerateError("mavlink names left after rename:\n" + "\n".join(leftovers[:20]))
        # Hand-written; their comments refer to MAVLink on purpose, so copy them last.
        if wire_protocol == "2.0":
            for path in FRAME_LAYER_SOURCES:
                shutil.copy(os.path.join(FRAME_C_DIR, path), staged)
        else:
            print(f"szlinkgen: warning: SZ-Link frame layer (szlink_frame.h) not generated: "
                  f"it needs wire protocol 2.0, not {wire_protocol}", file=sys.stderr)
        with open(os.path.join(staged, MARKER), "w", encoding="utf-8") as f:
            f.write("Generated by scripts/szlinkgen.py; this directory is replaced on every run.\n")
        if os.path.exists(output):
            shutil.rmtree(output)
        os.replace(staged, output)
    finally:
        if os.path.exists(staged):
            shutil.rmtree(staged)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output", "-o", required=True,
                        help="output directory (replaced if it was generated by this tool)")
    parser.add_argument("--lang", choices=LANGUAGES, default=DEFAULT_LANGUAGE,
                        help="C, or C++11 (C++11 headers plus the C headers); default: C")
    parser.add_argument("--wire-protocol", choices=WIRE_PROTOCOLS, default=DEFAULT_WIRE_PROTOCOL,
                        help="wire protocol version; default: 2.0 (needed by szlink_frame.h)")
    parser.add_argument("dialect", nargs="?", default=DEFAULT_DIALECT,
                        help="dialect XML (default: message_definitions/v1.0/spacezet.xml)")
    args = parser.parse_args(argv)
    if args.lang == "C++11" and args.wire_protocol != "2.0":
        parser.error("--lang C++11 needs --wire-protocol 2.0 (mavgen's C++11 generator "
                     "supports only 2.0)")
    try:
        generate(args.output, args.dialect, args.lang, args.wire_protocol)
    except GenerateError as e:
        print(f"szlinkgen: error: {e}", file=sys.stderr)
        return 1
    print(f"SZ-Link {args.lang} library generated in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
