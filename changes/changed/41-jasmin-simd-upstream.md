- The Advanced SIMD patches of the pinned Jasmin compiler are now the
  series proposed upstream as Jasmin `#1643`, carried with two upstream
  changes merged after the pin: Jasmin `#1633`, which replaces this
  project's patch lowering `a & !b` to BIC, and Jasmin `#1639`. See
  `toolchain/jasmin/PATCHES.md` and `toolchain/jasmin/PATCHES-SIMD.md`. The
  library's generated assembly is unchanged.
- In Jasmin code compiled with this toolchain, system calls are no longer
  assumed to preserve the vector registers: an ARMv8-A export function that
  issues one saves and restores q8-q15, and with `-call-conv windows`,
  ymm6-ymm15. On ARMv8-A, `>>s` by a constant on `u128` now lowers to SSHR
  and the constant 0 to MOVI, and the save slots of a large stack frame no
  longer produce loads and stores that do not assemble.
