- On x86-64 CPUs with AVX-512, the register clearing after key generation
  and signing also zeroes zmm16-zmm31 and the upper halves of zmm0-zmm15,
  whatever the variant. The Jasmin code does not use these registers, but
  the C library's `memcpy` can copy through them, and the testing library
  copies the seeds it is given with `memcpy`. `test_clearing` stores all of
  zmm0-zmm31 on such CPUs, finds a copy of SK.prf left in zmm31, and checks
  that the clearing removes it; on other CPUs it reports that part as NOT
  APPLICABLE. The AVX-512 mask registers, and the state of later extensions
  such as APX, are neither cleared nor inspected.
