- x86-64 hash kernels, selectable at build time: SHA-256 on the SHA
  extensions (`sha2/x86_64/shani/`), 4-way Keccak-f[1600] in AVX2
  (`keccak/x86_64/avx2/`), and 8-way SHA-256 and 4-way SHA-512 in AVX2
  (`sha2/x86_64/avx2/`). The kernels do not check for the CPU features they
  need; selecting them only on CPUs that have them is up to the build or
  the caller's dispatch.
