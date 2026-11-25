#!/usr/bin/env bash
# Generate the SZ-Link C library and run its tests.
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUT=${SZLINK_BUILD_DIR:-$(mktemp -d)}

python3 "$SRC_DIR/scripts/szlinkgen.py" --output "$OUT/include"
python3 -m unittest discover -s "$SRC_DIR/scripts" -p 'test_szlinkgen.py' -v

# Plain -O2 builds and a sanitizer build (the two lay out memory differently).
build_and_run() {
    local name=$1; shift
    gcc "$@" -Wall -Wextra -Werror -Wno-address-of-packed-member \
        -I"$OUT/include" "$SRC_DIR/szlink/c/test_szlink_frame.c" -o "$OUT/$name"
    "$OUT/$name"
}
build_and_run test_c99 -std=c99 -O2
build_and_run test_c11 -std=c11 -O2
build_and_run test_asan -std=c99 -O1 -g -fsanitize=address,undefined

# The generated headers must still build as C++.
echo '#include "spacezet/szlink.h"
#include "szlink_frame.h"' | g++ -std=c++11 -fsyntax-only -Wno-address-of-packed-member \
    -I"$OUT/include" -x c++ -
echo "SZ-Link tests passed"
