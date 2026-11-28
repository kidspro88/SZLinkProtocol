[![Build Status](https://github.com/kidspro88/SZLinkProtocol/workflows/Test%20and%20deploy/badge.svg)](https://github.com/kidspro88/SZLinkProtocol/actions)

# SZLink

SZLink is SpaceZet's very lightweight, header-only message library for communication between drones and/or ground control stations. It consists primarily of message-set specifications for different systems ("dialects") defined in XML files, and Python tools that convert these into source code. The SZ-Link frame layer (LCID + SEC framing, see [szlink/README.md](szlink/README.md)) sits on top of the generated messages.

> **Tip** SZLink is well suited for applications with very limited communication bandwidth. Its C implementation is optimized for resource-constrained systems with limited RAM and flash memory.

The message set and wire encoding are derived from the open MAVLink 2 standard; the code generator is the upstream `pymavlink` library (git submodule), whose output `scripts/szlinkgen.py` renames to the `szlink_*` / `SZLINK_*` / `namespace szlink` API.


## Quick start

### Generate C headers

To install the minimal SZLink environment on Ubuntu LTS 20.04, 22.04, or 24.04, enter the following on a terminal:

```bash
# Dependencies
sudo apt install python3-pip

# Clone the repository into the directory of your choice
git clone https://github.com/kidspro88/SZLinkProtocol.git --recursive
cd SZLinkProtocol

python3 -m pip install -r pymavlink/requirements.txt
```

You can then build the SZLink C library (wire protocol 2.0) for a dialect, e.g. `message_definitions/v1.0/spacezet.xml` (the default) or `common.xml`, as shown:

```bash
python3 scripts/szlinkgen.py --output generated/include/szlink
python3 scripts/szlinkgen.py --output generated/include/szlink message_definitions/v1.0/common.xml
# C++11 headers (*.hpp, also writes the C headers):
python3 scripts/szlinkgen.py --lang C++11 --output generated/include/szlink
```

### Use from cmake

To include the headers in cmake, install them locally, e.g. into the directory `install`:

```
cmake -Bbuild -H. -DCMAKE_INSTALL_PREFIX=install -DSZLINK_DIALECT=common -DSZLINK_VERSION=2.0
cmake --build build --target install
```

`-DSZLINK_ENABLE_CXX=OFF` skips the C++11 headers.

Then use `find_package` to get the dependency in `CMakeLists.txt`:

```
find_package(SZLink REQUIRED)

add_executable(my_program my_program.c)

target_link_libraries(my_program PRIVATE SZLink::szlink)
```

And pass the local install directory to cmake (adapt to your directory structure):

```
cd ../my_program
cmake -Bbuild -H. -DCMAKE_PREFIX_PATH=../SZLinkProtocol/install
```

For a full example, check [examples/c](examples/c) (C) or [examples/cpp](examples/cpp) (C++11).

*Note: even though we use `target_link_libraries` in cmake, it doesn't actually "link" to SZLink as it's just a header-only library.*

`-DSZLINK_VERSION=1.0` needs `-DSZLINK_ENABLE_CXX=OFF` (the C++11 generator supports only 2.0) and installs the message headers only, without the frame layer.

### SZ-Link frame layer

With wire protocol 2.0 the output (and the cmake install, under `include/szlink/`) also holds the frame layer: `szlink_frame.h`, `szlink_ecc.h`, `szlink_sec.h` and the Monocypher library (`monocypher.h`, `monocypher.c`) they use. In exactly one `.c` file of your program define the implementations, and compile `monocypher.c` with it:

```c
#define SZLINK_SEC_IMPLEMENTATION
#define SZLINK_ECC_IMPLEMENTATION
#include <szlink/spacezet/szlink.h>
#include <szlink/szlink_frame.h>
```

```
cc -I<prefix>/include my_program.c <prefix>/include/szlink/monocypher.c -o my_program
```

If your program already links its own Monocypher (3.1.x), do not compile the bundled `monocypher.c` (the `crypto_*` symbols would clash); point the frame layer at your copy instead, e.g. `-DSZLINK_SEC_MONOCYPHER_HEADER='<my/monocypher.h>'`.

Monocypher ships its own license text at the top of `monocypher.h`. See [szlink/README.md](szlink/README.md) for the frame format and API.

### Migrating from a MAVLink build

| Before | Now |
| --- | --- |
| `-DMAVLINK_DIALECT`, `-DMAVLINK_VERSION`, `-DMAVLINK_ENABLE_CXX` | `-DSZLINK_DIALECT`, `-DSZLINK_VERSION`, `-DSZLINK_ENABLE_CXX` |
| `find_package(MAVLink)` | `find_package(SZLink)` |
| target `MAVLink::mavlink` | target `SZLink::szlink` |
| `<prefix>/lib/cmake/MAVLink` | `<prefix>/lib/cmake/SZLink` |
| `#include <mavlink/<dialect>/mavlink.h>`, `mavlink_*` / `MAVLINK_*` | `#include <szlink/<dialect>/szlink.h>`, `szlink_*` / `SZLINK_*` |
| C++ `namespace mavlink`, `<mavlink/<dialect>/<dialect>.hpp>` | `namespace szlink`, `<szlink/<dialect>/<dialect>.hpp>` |
| env `MAVLINK_BASE_REF` (`scripts/check_api_break.py`) | env `SZLINK_BASE_REF` |
| `mavgenerate.py` | `szgenerate.py` |

`MAV_*` enum names and message names are unchanged.

### Other instructions

The generated C API follows the upstream MAVLink C API with the `szlink` prefix, so the upstream guide [Using C MAVLink Libraries (mavgen)](https://mavlink.io/en/mavgen_c/) applies after renaming `mavlink_*` to `szlink_*`.

> **Note:** The upstream guides [Installing the Toolchain](https://mavlink.io/en/getting_started/installation.html), [Generating Libraries](https://mavlink.io/en/getting_started/generate_libraries.html) and [Using Libraries](https://mavlink.io/en/getting_started/use_libraries.html) describe the underlying generator in more detail.


## Key Links

* [SZ-Link frame layer](szlink/README.md)
* [Upstream protocol documentation](https://mavlink.io/en/) (mavlink.io/en/)
* [Contributing](CONTRIBUTING.md)
* [License](COPYING)
