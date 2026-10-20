- `make memcheck` runs the tests of `make check` that call the library,
  on the application and the testing library, under Valgrind's memcheck,
  and CI runs it on Linux x86-64 and Linux AArch64. The known-answer tests
  and `test_memcheck` pass every buffer at its exact size on the heap, and
  a control with a one-byte-short public key buffer must be reported.
  Variants that need CPU extensions Valgrind does not emulate are not run
  under it (`shani` on x86-64 with Valgrind 3.26), and `test_core` is left
  out for its length. This is testing evidence, not a memory-safety
  verdict.
