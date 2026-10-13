- AArch64: a Keccak-f[1600] kernel that keeps the 25 lanes in
  general-purpose registers through all 24 rounds
  (`keccak/aarch64/scalar/`), selectable at build time in place of the
  portable kernel.
