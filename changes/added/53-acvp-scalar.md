- CI runs the NIST ACVP vectors a second time with the scalar variant
  forced for every set, on Linux x86-64, Linux AArch64 and macOS AArch64
  (`test-acvp-scalar`). The scalar variant is the one the correctness
  proofs cover, and no CI runner selects it on its own. The check fails
  unless the runner reports the forced scalar variant and all 1248 cases
  in 120 groups run and pass. It is a test result, not a CAVP validation.
