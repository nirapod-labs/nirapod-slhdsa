- On macOS, the compiler binaries built by `toolchain/build.sh` no longer
  record when the opam switch was built: `ar` and `ld` wrote file times into
  them, so building the same inputs again gave different binaries.
