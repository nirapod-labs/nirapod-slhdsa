# Architecture

How a call travels through the library, and why the code is cut where it is. The
contracts live in the sources each section names; this page is the map between
them.

```text
nirapod_slhdsa.h          the C API: twelve sets at run time, sizes, status codes
  capi/                   C wrapper: argument checks, variant dispatch, entropy,
                          timing mode, clearing
    unit <set>-<variant>  one Jasmin compilation unit: five exports
      src/slhdsa/         FIPS 205: addresses, WOTS+, XMSS, FORS, hypertree,
                          internal and external functions
        src/hash/         SHA-2, SHAKE, HMAC, MGF1; the kernels are the only
                          part a variant replaces
```

## The C API and the wrapper

[`include/nirapod_slhdsa.h`](../include/nirapod_slhdsa.h) declares the external
functions of FIPS 205 section 10 for all twelve parameter sets, selected at run time
by `nirapod_slhdsa_set`. The header owns every contract; [API](API.md) explains use.

The C layer under `capi/` does no cryptography. Every hash, every tree and the
message framing M' run in Jasmin. The wrapper does what needs the caller's lengths
or the operating system:

| File | Responsibility |
| :-- | :-- |
| `capi/api.c` | argument checks in their documented order, the call into the unit, the fault check of every new signature, clearing on every exit |
| `capi/sets.c` | the record of each compiled unit: sizes, exports, the CPU features its variant needs |
| `capi/dispatch.c` | the choice of variant for the running CPU, on every call, with nothing cached |
| `capi/entropy.c` | the only external service: the operating system's random source, for key generation and hedged signing |
| `capi/timing.c` | PSTATE.DIT around secret-dependent calls on AArch64 CPUs that have it |
| `capi/clear.c` | zeroing of the wrapper's own buffers and of caller-saved registers after secret-dependent calls |

The library has no heap allocation and no global mutable state. Its working memory
is the caller's stack; [API](API.md#stack-use) gives the measured depth.

## Compilation units

Each parameter set is compiled once per hash variant, as a separate Jasmin unit
(`src/slhdsa/sets/<set>.jinc`). Its parameters (n, h, d, h', a, k, m) are
compile-time constants from `src/slhdsa/params/<set>.jinc`, so every tree
dimension, key and signature size of a unit is fixed when it is compiled. The build wraps each unit in its own namespace,
which gives its exports distinct symbols (`capi/jasmin.h`):

| Export | FIPS 205 | Used by |
| :-- | :-- | :-- |
| `keygen` | Algorithm 18 on seeds the wrapper supplies | key generation |
| `sign` | Algorithms 22 and 23: framing, pre-hash, Algorithm 19 | every signing function |
| `verify` | Algorithms 24 and 25 | verification, and the fault check after signing |
| `sign_internal` | Algorithm 19 | the testing build only |
| `verify_internal` | Algorithm 20 | the testing build only |

The application library links these objects into one relocatable object and keeps
only the symbols of the header global; the Jasmin entry points are local. The
testing library (`capi/testing/`) adds the internal functions of FIPS 205 section 9,
key generation from given seeds and signing with a given `opt_rand`, for tests only.

## Hash variants and dispatch

A variant changes the hash kernels and nothing else. Every unit is built from the
same FIPS 205 source; only the include roots that name its kernels differ
(`Makefile`, "Kernel roots").

| Architecture | Variant | Sets | Kernels it replaces | Needs |
| :-- | :-- | :-- | :-- | :-- |
| AArch64, x86-64 | `scalar` | all | none; the portable kernels | the base architecture |
| x86-64 | `avx2` | all | four-way Keccak-f[1600] (SHAKE); the four-way SHA2 hashes, on 8-way SHA-256 and 4-way SHA-512 compression (SHA2) | AVX2, YMM state enabled by the OS |
| x86-64 | `shani` | SHA2 | SHA-256 compression | SHA extensions and AVX |
| AArch64 | `sha3` | SHAKE | single-way and four-way Keccak-f[1600] | Advanced SIMD and FEAT_SHA3 |
| AArch64 | `sha2` | SHA2 | SHA-256 and SHA-512 compression | Advanced SIMD, FEAT_SHA256, FEAT_SHA512 |

That gives 24 units on AArch64 and 30 on x86-64. On AArch64 the scalar
variant's single-way Keccak-f[1600] keeps the state in registers; its SHA-2 stays
on the portable compression functions on both architectures, because those are
the ones proven against FIPS 180-4.

`capi/dispatch.c` selects, at each call, the last variant of the set in the
order of the table whose features the operating system reports, and the scalar
variant if there is none. An x86-64 SHA2 set takes `shani` where the SHA
extensions are present, and `avx2` where only AVX2 is. The variants compute the
same function: `make check` requires every variant the host supports to give the
scalar variant's keys and deterministic signatures byte for byte.

## The FIPS 205 core

`src/slhdsa/` follows the standard's own structure, one file per section:

| File | FIPS 205 |
| :-- | :-- |
| `address.jinc` | section 4.2: the 32-byte ADRS and its setters (Table 1) |
| `encoding.jinc` | section 4: `toInt`, `base_2b`, n-byte moves (Algorithms 2 and 4) |
| `wots.jinc` | section 5: WOTS+ chains, key generation, signing (Algorithms 5 to 8) |
| `xmss.jinc` | section 6: XMSS nodes, signing, root from a signature (Algorithms 9 to 11) |
| `hypertree.jinc` | section 7: the d layers (Algorithms 12 and 13) |
| `fors.jinc` | section 8: k FORS trees (Algorithms 14 to 17) |
| `treehash.jinc` | the fold step that XMSS and FORS signing share |
| `internal.jinc` | section 9: the internal functions (Algorithms 18 to 20) |
| `external.jinc` | section 10: pure and pre-hash framing of M' |
| `thash_sha2*.jinc`, `thash_shake*.jinc` | section 11: PRF, PRF_msg, H_msg, F, H and T_l |
| `api.jinc` | the exports of a unit, the boundary to the C wrapper |

Each file's introduction states the representation it relies on, such as byte
order and index arithmetic, and the FIPS 205 lines it follows. `src/slhdsa/hook/` holds two points where
a test build may perturb signing, used only by the fault tests.

## The hash layer

`src/hash/` implements SHA-224 to SHA-512/256, SHA3-224 to SHA3-512, SHAKE128,
SHAKE256, HMAC and MGF1 from FIPS 180-4, FIPS 202, FIPS 198-1 and RFC 8017. A
*kernel* is the part a variant replaces: the Keccak-f[1600] permutation and the two
SHA-2 compression functions, single-way or multi-way. Everything above it
(sponge, buffering, padding, HMAC, MGF1) is one source for every target.
[`src/hash/README.md`](../src/hash/README.md) lists every kernel and its state.

## From source to machine code

The pinned Jasmin compiler ([TOOLCHAIN](TOOLCHAIN.md)) turns each unit into
assembly for its target (`-arch armv8a` or `-arch x86-64`, Mach-O or ELF). The
build assembles that assembly with the platform's assembler and links it with the
wrapper. The repository carries the assembly of all three targets in `gen/`, with
`gen/MANIFEST`, so the library builds with a C toolchain alone; with `JASMINC`
set, the build compiles the Jasmin sources itself instead. The `.jazz` and
`.jinc` sources are the form to modify; `gen/` is their compiled output.
`make gen` writes the assembly of all three targets with the manifest, and
`make gen-check` regenerates it and fails on any byte difference. Each
generated file opens with a comment block that names its licence, unit and
target, the CPU features the unit needs and how to regenerate it; the block
depends on nothing but the unit and the target.

The compiler zeroes each export's stack frame before it returns
(`-stack-zero loop`). On x86-64 its register allocation uses rbp as a general
register; [API](API.md#known-limitations) states what that means for frame-chain
walkers.
