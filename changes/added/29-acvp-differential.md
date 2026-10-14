- The full NIST ACVP SLH-DSA vectors (1248 cases: key generation, signing
  and verification, internal and external interfaces, pure and the twelve
  pre-hash functions, deterministic and hedged) run in CI on every
  platform, against the library's testing build: the same Jasmin code and
  C sources, plus entry points that take given seeds and randomness. The
  vector files are pinned by commit and SHA-256 and fetched at test time.
- A differential test compares the library with slhdsa-c, an independent
  implementation pinned by commit, on seeded random inputs for every
  parameter set and interface. Adapters for OpenSSL, wolfSSL, BoringSSL and
  the SPHINCS+ reference code let the same drivers run against those
  baselines by hand; they are not part of CI.
