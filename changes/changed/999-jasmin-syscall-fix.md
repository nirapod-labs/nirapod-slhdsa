- The pinned Jasmin compiler now carries its system-call fix in the form
  merged upstream as Jasmin `#1640`, where each calling convention lists
  the registers that a system call preserves, in place of the earlier form
  that came with Jasmin `#1643`. The compiler assumes the same registers
  preserved as before, and the library's generated assembly is unchanged.
