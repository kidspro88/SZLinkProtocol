# Simple C++ example

Simple example receiving and sending SZLink messages (MAVLink v2 wire format) over UDP based on POSIX APIs (e.g. Linux, BSD, macOS).

This is the C++11 counterpart to the [C example](../c). Instead of the C pack/decode functions it uses the generated message structs (e.g. `szlink::minimal::msg::HEARTBEAT`) together with `szlink::MsgMap` to serialize and deserialize to and from a `szlink_message_t`.

> **Note** The C++11 library requires the user to provide a `szlink::szlink_get_msg_entry()` function so that `szlink_parse_char()` can look up the length and CRC extra of incoming messages.
> This example builds it from the dialect's `MESSAGE_ENTRIES` table (see the top of `udp_example.cpp`).

## Install SZLink

In top level directory, build and install the SZLink headers locally into the install folder:

```
cmake -Bbuild -H. -DCMAKE_INSTALL_PREFIX=install
cmake --build build --target install
```

This installs both the C (`*.h`) and C++11 (`*.hpp`) headers.

## Build example

In the example directory, build the example while passing the local install directory:

```
cd examples/cpp
cmake -Bbuild -H. -DCMAKE_PREFIX_PATH=$(pwd)/../../install
cmake --build build
```
