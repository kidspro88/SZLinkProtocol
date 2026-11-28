# Simple C example

Simple example receiving and sending SZLink messages (MAVLink v2 wire format) over UDP based on POSIX APIs (e.g. Linux, BSD, macOS).

## Install SZLink

In top level directory, build and install the SZLink headers locally into the install folder:

```
cmake -Bbuild -H. -DCMAKE_INSTALL_PREFIX=install
cmake --build build --target install
```

## Build example

In the example directory, build the example while passing the local install directory:

```
cd examples/c
cmake -Bbuild -H. -DCMAKE_PREFIX_PATH=$(pwd)/../../install
cmake --build build
```
