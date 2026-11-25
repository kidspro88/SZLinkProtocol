#!/usr/bin/env bash
# Generate the SZ-Link C library and run its tests.
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
if [ -n "${SZLINK_BUILD_DIR:-}" ]; then
    OUT=$SZLINK_BUILD_DIR
else
    OUT=$(mktemp -d)
    trap 'rm -rf "$OUT"' EXIT
fi

python3 "$SRC_DIR/scripts/szlinkgen.py" --output "$OUT/include"
python3 -m unittest discover -s "$SRC_DIR/scripts" -p 'test_szlinkgen.py' -v
# Python reference implementation (ground station): needs `cryptography`
python3 -m unittest discover -s "$SRC_DIR/szlink/python/tests" -v

# Plain -O2 builds and a sanitizer build (the two lay out memory differently).
C_DIR="$SRC_DIR/szlink/c"
MONOCYPHER="$C_DIR/third_party/monocypher"
build_and_run() {
    local name=$1; shift
    local test
    for test in test_szlink_frame test_szlink_sec test_szlink_ecc; do
        gcc "$@" -Wall -Wextra -Werror -Wno-address-of-packed-member \
            -I"$OUT/include" -I"$C_DIR" -I"$MONOCYPHER" \
            "$C_DIR/$test.c" "$MONOCYPHER/monocypher.c" -o "$OUT/${name}_$test"
        "$OUT/${name}_$test"
    done
}
build_and_run c99 -std=c99 -O2
build_and_run c11 -std=c11 -O2
build_and_run asan -std=c99 -O1 -g -fsanitize=address,undefined

# The generated headers must still build as C++.
# (with the implementations, as the ArduPilot port compiles them)
printf '#define SZLINK_SEC_IMPLEMENTATION\n#define SZLINK_ECC_IMPLEMENTATION\n#include "spacezet/szlink.h"\n#include "szlink_frame.h"\n' |
    g++ -std=c++11 -fsyntax-only -Wall -Wextra -Werror -Wno-address-of-packed-member \
    -I"$OUT/include" -I"$C_DIR" -I"$MONOCYPHER" -x c++ -
echo "SZ-Link tests passed"
