# MRK C SDK

`mrk-ffi` exposes the Rust `mrk-sdk` implementation through a blocking C ABI. It does not contain a second protocol or cryptography implementation.

Build the shared and static libraries from the workspace root:

```bash
cargo build --release --offline -p mrk-ffi
```

Linux outputs:

```text
target/release/libmrk.so
target/release/libmrk.a
mrk-ffi/include/mrk_sdk.h
```

Compile the version example:

```bash
cc mrk-ffi/examples/version.c \
  -Imrk-ffi/include \
  -Ltarget/release \
  -Wl,-rpath,"$PWD/target/release" \
  -lmrk \
  -o target/version-example

./target/version-example
```

The network API is blocking and owns an internal Tokio runtime. Applications should call it from worker threads. A stream permits one reader and one writer concurrently; calls in the same direction must be serialized. See `include/mrk_sdk.h` for ownership and shutdown requirements.
