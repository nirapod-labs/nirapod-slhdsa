- `test_clearing` runs key generation, every signing path and internal
  signing twice, on inputs that differ only in SK.seed, SK.prf and
  opt_rand, for every set and every variant the host runs, and the public
  functions on the application library. No byte of the stack below the
  call and no caller-saved register, stored the moment the library
  function returns, may differ between the two runs. Controls leave a copy
  of SK.prf in a frame and in single registers, AArch64 x8 among them and
  x18 on Linux, and must be found; builds without the register clearing
  or without stack zeroization must show residue. A secret-dependent value
  that is equal for both inputs is not seen, and on x86-64 the AVX-512
  register state is not stored.
- The residue scan of `test_stack` covers the internal signing and
  verification exports, and `test_registers` stores the registers as the
  library function returns rather than after the test's own wrapper.
- `make asm-policy` checks more of the emitted code: every export has one
  RET, reached only through the stack-zeroing epilogue, with no branch past
  it or into the export from elsewhere; branches and calls stay in the unit
  and are direct; no trap, system call or system-register instruction; a
  speculation barrier before the first call; no data directive in a code
  section. On AArch64 every instruction is checked against the
  data-independent-time list of DDI 0487 M.d. The x86-64 emitted code is
  not checked against Intel's list.
- `make ct` also runs `jasmin-ct --doit` after the `slhlowering` pass on
  every unit of both architectures, with a control per architecture that
  it must reject.
