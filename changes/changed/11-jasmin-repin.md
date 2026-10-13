- The Jasmin pin moves to upstream main at `e8f59794c` (2026-10-12), which
  includes jasmin-lang/jasmin#1616 and #1621; the series no longer carries
  them. Upstream #1594, #1624 and #1625 are carried at their current heads,
  #1617 as a port to the new instruction descriptors, and #1632 in place of
  this project's patch for invalid instruction operands. See
  `toolchain/jasmin/PATCHES.md`.
- ARMv8-A: x29, the frame pointer, is never allocated, so stack traces taken
  on macOS stay valid inside compiled functions. A zero-extending word load
  from a global array now compiles; it stopped with an error at assembly
  printing.
- The safety checker shares abstract values that do not change, prints the
  constraints of a relational value in sorted order, and has new
  configuration options (`array_track_max_bytes`, `congruence_reduction`,
  `relational_loop_vars`, `relational_loop_vars_in`) that trade precision
  for speed. Their defaults keep the previous analysis, and other values can
  only add alarms.
