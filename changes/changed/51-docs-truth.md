- `docs/PROOFS.md` has a table of which hash variant each CPU runs and
  whether that variant is proven: only the scalar variants are, and the
  library selects another variant on every CPU with the extensions it needs,
  with no way for an application to request the scalar one. It also
  describes how an ACVP run on the scalar variant would test the
  specification through the correctness theorems, and under which
  conditions; no result of that run is recorded.
- The proof pages state two more limits: the EUF-CMA theorems are about
  classical adversaries, and for the SHA2 sets the specification extends
  SHA-2 past the input length of FIPS 180-4, so on longer messages those
  theorems are about that extension rather than FIPS 205. The status
  paragraph of `proofs/README.md` now describes the correctness theorems of
  the exports.
- The security model names return prediction (Spectre-RSB) and store-to-load
  forwarding (Spectre v4) as outside the speculative constant-time model;
  speculative store bypass disable is left to the platform.
- `docs/API.md` lists the supported platforms (Linux on x86-64 and AArch64,
  macOS on AArch64), states the interface stability policy before 1.0.0, and
  points out that using one key for both hedged and deterministic signing is
  outside the security theorems.
