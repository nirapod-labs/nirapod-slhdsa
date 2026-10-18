- The security documentation no longer says that the compiler's proofs
  carry the constant-time results to the assembly. They are proofs of
  semantic preservation and state nothing about leakage. The pages now say
  which compiler stage each check sees and what checks the emitted code:
  `dit.awk` on AArch64, nothing on x86-64.
