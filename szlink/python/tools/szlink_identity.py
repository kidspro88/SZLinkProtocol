#!/usr/bin/env python3
"""Create or show an SZ-Link identity file (ground station key).

  szlink_identity.py new gcs.key     # writes a new secret key (mode 600)
  szlink_identity.py show gcs.key    # public key and fingerprint
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from szlink import crypto  # noqa: E402
from szlink.pairing import Identity  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=["new", "show"])
    parser.add_argument("path")
    args = parser.parse_args()
    if args.command == "new":
        Identity.generate().save(args.path)
    ident = Identity.load(args.path)
    print(f"public key  {ident.public.hex()}")
    print(f"fingerprint {crypto.fingerprint(ident.public)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
