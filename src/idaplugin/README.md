# Hex-Rays demo

This repository demonstrates how to use the extensive, but often not self-evident, functionality provided by [IDA SDK](https://www.hex-rays.com/products/ida/support/sdkdoc/index.html) in order to put together a plugin with Hex-Rays-like capabilities.

# Build and Installation

This will build the plugin using the specified IDA SDK (7.3+), and install it into the specified IDA:
```
mkdir build
cd build
cmake .. -DIDA_SDK_DIR=<path_to_ida_sdk> -DIDA_DIR=<path_to_ida>
make
make install
```

# Run

This is a demonstration plugin which works only with the provided `ack.x86.gcc.O0.g.elf` binary:
1. Build and install the plugin.
2. Open the `ack.x86.gcc.O0.g.elf` binary in IDA.
3. Navigate to `main() @ 0x8048577` or `ack() @ 0x804851C` and hit `Ctrl+Shift+D` to trigger the plugin. The function gets decompiled and you can interact with the result the same way you would in Hex-Rays. Only decompilation of these two functions is implemented.

![](doc/master.gif)
