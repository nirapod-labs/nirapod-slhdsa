# Validation

How the implementation is tested against FIPS 205, against other
implementations, and against misuse; what each test establishes and where it runs.
No test uses the implementation as its own oracle. [STATUS](STATUS.md) has the
current results.

## Where tests run

CI runs every check below natively on three hosted runners, on every pull request
it can affect and on every push to `main`:

| Platform | Runner CPU features the checks require | Hash variants exercised |
| :-- | :-- | :-- |
| Linux x86-64 | AVX2, SHA extensions | `scalar`, `avx2`, `shani` |
| Linux AArch64 | FEAT_SHA512, FEAT_SHA3 | `scalar`, `sha2`, `sha3` |
| macOS AArch64 | FEAT_SHA512, FEAT_SHA3 | `scalar`, `sha2`, `sha3` |

A check that needs a CPU feature the runner lacks fails instead of skipping
(`ci/cpu-has.sh`), so a runner change cannot silently drop a variant.
`ci/checks.toml` lists every check with the files it reads; a check runs again
whenever one of them changes.

## NIST ACVP vectors

`tests/acvp/` runs the SLH-DSA vectors of NIST's ACVP server, pinned by commit
and file digest (`tests/vectors/`): key generation, signature generation and
signature verification, for all twelve sets, the internal and external
interfaces, pure and pre-hash with the twelve pre-hash functions, deterministic
and with a given `opt_rand`. That is 1248 cases in 120 groups; the check passes
only if every case runs and passes, so a case the runner cannot run counts against
it. The runner uses the testing library, which accepts given seeds and `opt_rand`,
and the hash variant the CPU selects. Passing the ACVP vectors in CI is a test
result, not a CAVP validation or certification.

Controls (`tests/acvp/controls.py`): runs that flip the computed result, or the
expected one, must fail every case, so a runner that accepts everything cannot
pass. A runner built on a stub implementation checks the verdict rules themselves
(`tests/acvp/verdicts.py`).

`make check` also runs a 52-case subset (`tests/core/acvp-subset.txt`) through
both the testing and the application library. In the application library, key
generation cannot take given seeds nor signing a given `opt_rand`, so those cases
are reported NOT RUN there. A control requires the subset test to reject a case
whose expected signature or verdict was changed.

## Differential tests

`tests/diff/` runs this library and another implementation as separate processes
on the same inputs, derived from a recorded seed, and compares every output byte
for byte: key generation from seeds; signing internal and external, pure and with
each pre-hash function, deterministic and hedged with a fixed `opt_rand`;
verification of the signature and of four corrupted forms. Twenty-eight
combinations per set make 336 cases.

CI compares against [slhdsa-c](https://github.com/pq-code-package/slhdsa-c) at
`174c02e`. Adapters for OpenSSL, wolfSSL, BoringSSL and the SPHINCS+ reference
exist under `tests/diff/adapters/` with their pins in `bench/`; CI does not run
them. Controls corrupt the other side's keys, signatures or verdicts and require
the comparison to report mismatches.

Agreement shows byte equality on the inputs run. Two independent codebases agreeing
makes a shared misreading of FIPS 205 less likely without excluding it; the ACVP
vectors are the external reference.

## Negative and fault tests

Through the public API (`tests/negative/test_negative.c`): NULL pointers, unknown
sets, wrong buffer lengths, contexts of 256 bytes, pre-hash values outside the
enum, several wrong arguments at once, overlapping buffers, each with its
documented status and output state; and tampered signatures with one flipped bit
in R, in the FORS part, and in the first, a middle and the last hypertree layer,
changed messages, contexts and public keys, truncated and extended signatures.

`tests/negative/test_fault.c` flips a bit of the FORS public key or of a layer-0
XMSS root during signing and requires the fault check to withhold the signature.
`tests/negative/test_entropy.c` makes the operating system's random source fail
and requires key generation and hedged signing to fail with zeroed outputs.

## ABI tests

`tests/abi/` checks the compiled library rather than its outputs:

- the archive exports exactly the functions of the header, and a control archive
  with one extra global function is rejected;
- stack depth and residue: no byte of SK.seed, SK.prf or `opt_rand` remains on the
  stack below the caller after a call, and a build without stack zeroization is
  seen to leave residue;
- registers: no caller-saved register holds secret-key bytes after a call, and
  PSTATE.DIT is set during secret-dependent work on AArch64 CPUs that have it.

[API](API.md) gives the measured figures and the limits of each scan.

## Hash layer

`tests/hash/` tests each hash function and kernel variant against NIST CAVP
vectors and known answers, differentially against OpenSSL's libcrypto in normal
and 0xa5-filled builds, and over every length, rate and start position
of the SHAKE squeeze, with negative controls that must be detected.
[`tests/hash/README.md`](../tests/hash/README.md) gives the detail.

## Fill check

The core writes zeros into some buffers before use so that the safety checker
can follow them. `make fill-check` rebuilds the library with those fills writing
0xa5 bytes and runs the known answers and core tests on it, which shows that no
result depends on the fill value. On Linux AArch64, CI also builds one control per
fill site, made to depend on the fill, and each must fail.

## Running them

From the repository root, with the pinned toolchain on `PATH`:

```sh
make check JASMINC=jasminc                  # core, negative, fault, ABI, ACVP subset
make -C tests/acvp check IMPL=nirapod       # the full ACVP vectors
python3 ci/check.py run differential linux-x86_64   # a CI check, as CI runs it
```

`ci/check.py run <check> <platform>` runs any check of `ci/checks.toml` on a host
of that platform, with the recipe CI uses.
