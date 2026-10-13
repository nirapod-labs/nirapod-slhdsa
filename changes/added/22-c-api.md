- A C API for SLH-DSA (`include/nirapod_slhdsa.h`): key generation, hedged and
  deterministic signing and verification, pure and with the twelve pre-hash
  functions of the NIST hash identifiers (SHA-2, SHA-3, SHAKE), with context
  strings, for all twelve parameter sets. Each signature is verified before it
  is returned. On x86-64 a variant using AVX2 (SHAKE sets) or the SHA
  extensions (SHA2 sets) is chosen per call where the CPU has them. The FIPS
  205 internal functions are only in a separate testing library. The stack use
  of each function is in `docs/API.md`.
