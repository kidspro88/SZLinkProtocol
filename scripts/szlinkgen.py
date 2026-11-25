#!/usr/bin/env python3
"""Generate the SZ-Link C library.

Runs pymavlink's mavgen (C, wire protocol 2.0) on a dialect, then renames every
``mavlink``/``MAVLINK``/``MAVLink`` identifier, file name and comment to
``szlink``/``SZLINK``/``SZLink`` and adds the SZ-Link frame layer
(``szlink/c/szlink_frame.h``).

Usage::

    python3 scripts/szlinkgen.py --output build/szlink
    # then:  #include "spacezet/szlink.h"  and  #include "szlink_frame.h"

``MAV_*`` enums (MAV_TYPE, MAV_CMD, ...) keep their names: they are protocol
values, not code, and keeping them lets SZ-Link telemetry stay readable by
standard MAVLink tooling.
"""

import argparse
import os
import re
import shutil
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DIALECT = os.path.join(REPO_ROOT, "message_definitions", "v1.0", "spacezet.xml")
FRAME_HEADER = os.path.join(REPO_ROOT, "szlink", "c", "szlink_frame.h")

_RENAMES = [
    (re.compile("MAVLINK"), "SZLINK"),
    (re.compile("MAVLink"), "SZLink"),
    (re.compile("Mavlink"), "Szlink"),
    (re.compile("mavlink"), "szlink"),
]

_LEFTOVER = re.compile("mavlink", re.IGNORECASE)


def rename_text(text):
    """Rename every mavlink spelling in ``text`` to its szlink spelling."""
    for pattern, replacement in _RENAMES:
        text = pattern.sub(replacement, text)
    return text


def find_leftovers(root):
    """Return ``path:line`` for every remaining mavlink spelling under ``root``."""
    hits = []
    for dirpath, _, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            if _LEFTOVER.search(name):
                hits.append(path)
            with open(path, encoding="utf-8", errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    if _LEFTOVER.search(line):
                        hits.append(f"{path}:{lineno}")
    return hits


def rename_tree(src, dst):
    """Copy ``src`` to ``dst``, renaming file names and file contents."""
    for dirpath, _, files in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        out_dir = os.path.join(dst, rename_text(rel)) if rel != "." else dst
        os.makedirs(out_dir, exist_ok=True)
        for name in files:
            with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                text = f.read()
            with open(os.path.join(out_dir, rename_text(name)), "w", encoding="utf-8") as f:
                f.write(rename_text(text))


def run_mavgen(dialect, output):
    sys.path.insert(0, REPO_ROOT)  # use the pymavlink submodule
    from pymavlink.generator import mavgen

    opts = mavgen.Opts(output, wire_protocol="2.0", language="C", validate=True,
                       strict_units=True)
    if not mavgen.mavgen(opts, [dialect]):
        raise RuntimeError(f"mavgen failed for {dialect}")


def generate(output, dialect=DEFAULT_DIALECT):
    with tempfile.TemporaryDirectory() as tmp:
        run_mavgen(dialect, tmp)
        if os.path.exists(output):
            shutil.rmtree(output)
        rename_tree(tmp, output)
    leftovers = find_leftovers(output)
    if leftovers:
        raise RuntimeError("mavlink names left after rename:\n" + "\n".join(leftovers[:20]))
    # Hand-written; its comments refer to MAVLink on purpose, so copy it last.
    shutil.copy(FRAME_HEADER, output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output", "-o", required=True, help="output directory (replaced)")
    parser.add_argument("dialect", nargs="?", default=DEFAULT_DIALECT,
                        help="dialect XML (default: message_definitions/v1.0/spacezet.xml)")
    args = parser.parse_args(argv)
    generate(args.output, args.dialect)
    print(f"SZ-Link C library generated in {args.output}")


if __name__ == "__main__":
    main()
