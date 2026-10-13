# Hash primitive tests

Tests for the Jasmin hash primitives of `src/jasmin/hash`. They run the
production code paths natively through test exports, compare their output
with NIST vectors and an independent implementation, and check the source
with the Jasmin constant-time type checkers.

Results are not recorded here; each run prints its own summary, and
recorded results carry the revision and host they were obtained on.

## Contents

| Path | Role |
|---|---|
| `jasmin/hash_test.jazz` | test compilation unit: every test export |
| `jasmin/test_keccak.jinc` | exports for Keccak-f, the sponge, SHA-3 and SHAKE |
| `jasmin/test_sha2.jinc` | exports for SHA-2 (one-shot, incremental, compression) and HMAC |
| `jasmin/test_arrays.jinc` | generated: array instances at lengths 1, 7, 16, 22, 32, 64, 65, 129, 200 (single-way and multi-way), and MGF1 at the FIPS 205 sizes |
| `jasmin/array_io.jinc` | copy between C memory and a fixed-length stack array |
| `c/hash_test.c` | C harness: CAVP and differential modes |
| `c/hash_test_exports.h` | C prototypes of the test exports |
| `c/openssl_min.h` | the libcrypto entry points the differential mode calls |
| `vectors/fetch.sh` | fetch and verify the NIST CAVP response files |
| `tools/check_constants.py` | recompute every constant table from its definition |
| `tools/gen_test_arrays.py` | generator of `jasmin/test_arrays.jinc` |
| `tools/negative_control.sh` | show that the tests detect a wrong round constant |

The test exports are named `nirapod_slhdsa_hashtest_*`. They are linked
into the test binary only, never into the library.

## What each check establishes

**CAVP** (`hash_test cavp <dir>`). The NIST CAVP byte-oriented response
files for SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256,
SHA3-224 .. SHA3-512, SHAKE128 and SHAKE256: every ShortMsg, LongMsg and
Monte Carlo case, and the SHAKE VariableOut cases. HMAC.rsp is run for its
SHA-256 (`L=32`) and SHA-512 (`L=64`) sections; its SHA-1, SHA-224 and
SHA-384 sections are counted and reported as not applicable. The Monte
Carlo procedures are those of SHAVS and SHA3VS and are restated in the
harness. These cases exercise the one-shot exports and, through them,
absorb, finalize and squeeze from memory. The same run checks the
Keccak-f[1600] export alone against the two permutation examples in XKCP's
`KeccakF-1600-IntermediateValues.txt`.

**Differential** (`hash_test diff <seed> <n>`). `n` iterations of seeded
random cases compared with libcrypto (OpenSSL 3), which shares no code with
this implementation:

- SHA-3 and SHAKE through the incremental exports, with the message and
  the output each split at random points, and through the one-shot exports;
- SHA-2 one-shot, and incremental with random split points;
- SHA-256 and SHA-512 finalize alone, with totals up to `2^61 - 1` bytes,
  against the padding and length laid out in C and compressed by the
  compression export;
- the array and pointer forms of each compression function against each
  other;
- HMAC-SHA-256 and HMAC-SHA-512 with keys below, at and above one block;
- MGF1 at the six FIPS 205 sizes, against MGF1 composed in C from
  libcrypto SHA-2;
- every array instance, after a random prefix absorbed through the memory
  form and, for squeezing, after a random number of bytes already output
  and followed by more output from the position it returns;
- the 4-way Keccak permutation against four single-way permutations, the
  4-way init on a random state, and the 4-way sponge per instance against
  libcrypto for all six SHA-3 and SHAKE domains, over two absorbed and two
  squeezed arrays;
- the 8-way SHA-256 and 4-way SHA-512 compressions against the single-way
  compression of every instance, and their absorb and finalize layer per
  instance against libcrypto for every SHA-2 initial value;
- the 8-way SHA-256 and 4-way SHA-512 finalize alone, with totals up to
  `2^61 - 1` bytes, per instance against the padding and length laid out
  in C and compressed by the single-way compression export.

Message lengths concentrate on every rate and block boundary. The seed and
the libcrypto version are printed; a failure prints its inputs.

**Constants** (`make constants`). Recomputes the SHA-2 round constants and
initial values from roots of primes and the SHA-512/t generation function,
and the Keccak round constants from the LFSR of FIPS 202, and compares them
with the tables in the source.

**Generated source** (`make generated`). Regenerates
`jasmin/test_arrays.jinc` and fails if the committed file differs.

**Negative control** (`make negative-control`). Flips one bit of one round
constant in each of Keccak, SHA-256 and SHA-512 in a copy of the sources,
builds it with the selected kernel variants, runs CAVP and a short
differential run, and requires a failure in every family the Makefile
lists: the three single-way families,
and the three multi-way kernels. Every kernel variant reads the shared
constant tables, so the control covers the variants selected for the run.

**CT and SCT** (`make ct`, `make sct`). `jasmin-ct` and `jasmin-ct --sct`
over the whole test unit, which covers every export and, through them,
every library function in `src/jasmin/hash`. Both checkers assume program
safety, which these targets do not establish. They type-check the source
before compilation; the connection to emitted code is the compiler's.

A PASS of these checks means: the listed cases produced the expected
bytes, or the checker accepted the program, on the stated build and host.
It is not a proof of correctness, of safety or of timing behaviour.

## Fail-closed behaviour

The harness exits non-zero when any comparison fails, when a response
file is missing or unreadable, when a file has no cases, when a record is
malformed or inconsistent, when a Monte Carlo file has other than 100
checkpoints, or when a libcrypto call fails. `fetch.sh` stops on any
download failure or SHA-256 mismatch and leaves no partial vector
directory. The negative control fails when a mutation does not match its
source text, when the mutated build fails, or when any family goes
undetected.

## Running

From the repository root, with `jasminc` and `jasmin-ct` on `PATH` or named
by `JASMINC` and `JASMIN_CT`:

```sh
make -C tests/hash vectors        # network: fetch and verify the CAVP files
make -C tests/hash check          # build for this machine and run both modes
make -C tests/hash ct sct
make -C tests/hash constants generated
make -C tests/hash negative-control
```

For a target whose host has no Jasmin compiler, generate the assembly
elsewhere and build there:

```sh
make -C tests/hash asm negative-control-asm ARCH=x86_64 SYSTEM=linux   # any host with jasminc
make -C tests/hash check-prebuilt negative-control-prebuilt             # the x86-64 host
```

`DIFF_SEED` and `DIFF_ITERS` set the differential seed and iteration count.
`KECCAK_VARIANT`, `KECCAKX_VARIANT`, `SHA2_VARIANT` and `SHA2X_VARIANT` select
kernel variant directories (the same values in both steps of a cross-host run).
On AArch64, the register-resident Keccak kernel:

```sh
make -C tests/hash check KECCAK_VARIANT=aarch64/scalar
```

## Vector provenance

`vectors/fetch.sh` downloads four archives from the NIST Cryptographic
Algorithm Validation Program and checks each against a pinned SHA-256:

| Archive | SHA-256 |
|---|---|
| `shs/shabytetestvectors.zip` | `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8` |
| `sha3/sha-3bytetestvectors.zip` | `cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c` |
| `sha3/shakebytetestvectors.zip` | `debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7` |
| `mac/hmactestvectors.zip` | `418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd` |

The response files are works of the US Government. They are fetched at test
time and not stored in the repository.
