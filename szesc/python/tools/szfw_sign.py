#!/usr/bin/env python3
"""Sign a SpaceZet ESC firmware binary into an .szfw image.

  szfw_sign.py --key esc_signing.key --board 1 --version 0x00010200 esc.bin esc.szfw
  szfw_sign.py --verify --pubkey <hex> esc.szfw

Keys are SZ-Link identity files (szlink/python/tools/szlink_identity.py new FILE).
The ESC trusts the matching public key at index --key-id.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "szlink", "python"))

import szfw  # noqa: E402
from szlink import crypto  # noqa: E402
from szlink.pairing import Identity  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--key", help="identity file of the signing key")
    parser.add_argument("--key-id", type=int, default=0)
    parser.add_argument("--board", type=lambda v: int(v, 0), default=1)
    parser.add_argument("--version", type=lambda v: int(v, 0), default=1)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--pubkey", action="append", default=[], help="trusted key (hex), in key_id order")
    parser.add_argument("input")
    parser.add_argument("output", nargs="?")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()
    if args.verify:
        keys = [bytes.fromhex(k) for k in args.pubkey]
        st = szfw.verify_image(data, keys)
        hdr = szfw.Header.parse(data)
        print(f"board {hdr.board_id} version 0x{hdr.fw_version:08x} {hdr.body_size} bytes "
              f"key {hdr.key_id}: {szfw.STATUS_NAMES[st]}")
        return 0 if st == szfw.STATUS_OK else 1
    if not args.key or not args.output:
        parser.error("--key and output are needed to sign")
    ident = Identity.load(args.key)
    image = szfw.sign_image(ident.seed, data, args.board, args.version, args.key_id)
    with open(args.output, "wb") as f:
        f.write(image)
    print(f"signed {len(data)} bytes with {crypto.fingerprint(ident.public)} -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
