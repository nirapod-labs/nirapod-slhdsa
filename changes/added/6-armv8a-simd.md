- Advanced SIMD for the ARMv8-A target of the pinned Jasmin compiler
  (`toolchain/jasmin/patches-simd/`): the vector registers V0-V31 and their
  calling convention, basic vector operations, the SHA-256, SHA-512 and SHA-3
  instructions, and lane permutations and element moves. The instruction
  semantics are transcribed from the Arm manual and trusted, and their
  data-independent timing holds only while the caller sets PSTATE.DIT; see
  `toolchain/jasmin/PATCHES-SIMD.md`.
