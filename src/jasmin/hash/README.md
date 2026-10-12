# Hash primitives

Jasmin implementations of the hash functions that SLH-DSA (FIPS 205) needs:

| Family | Functions | Standard |
|---|---|---|
| Keccak | Keccak-f[1600], sponge, SHA3-224/256/384/512, SHAKE128, SHAKE256 | FIPS 202 |
| SHA-2, 32-bit words | SHA-224, SHA-256 | FIPS 180-4 |
| SHA-2, 64-bit words | SHA-384, SHA-512, SHA-512/224, SHA-512/256 | FIPS 180-4 |
| MAC | HMAC-SHA-256, HMAC-SHA-512 | FIPS 198-1 |
| Mask generation | MGF1-SHA-256, MGF1-SHA-512 | RFC 8017, B.2.1 |

FIPS 205 section 11 builds its tweakable hash functions from these. The
SLH-DSA functions themselves (`F`, `H`, `T_l`, `PRF`, `PRF_msg`, `H_msg`) are
composed by the caller from the interfaces below. The pre-hash functions of
HashSLH-DSA (FIPS 205 section 10.2.2) are the one-shot forms of the same
primitives.

Everything here is internal Jasmin: no symbol in this directory is exported
from the library. The test exports live in `tests/hash/`, and
`tests/hash/README.md` says what each test establishes.

## Files and kernel variants

```
keccak/keccak_constants.jinc round count, ι constants and ρ offsets, shared by the kernels
keccak/keccakf1600.jinc    Keccak-f[1600] kernel (scalar)
keccak/keccakf1600_x4.jinc 4-way Keccak-f[1600] kernel (scalar, four single-way calls)
keccak/sponge.jinc         incremental sponge, memory input and output
keccak/sponge_array.jinc   the same for fixed-length arrays (instance file)
keccak/fips202.jinc        one-shot SHA-3 and SHAKE from memory
keccak/sponge_x4.jinc      4-way sponge: init and finalize
keccak/sponge_x4_array.jinc 4-way absorb and squeeze of fixed-length arrays (instance file)
keccak/aarch64/scalar/     Keccak-f[1600] kernel for AArch64 with the state in registers
sha2/sha256_k.jinc         SHA-256 round constants, shared by its kernels
sha2/sha256_compress.jinc  SHA-256 compression kernel (scalar)
sha2/sha256.jinc           SHA-224/256 initial values, buffering, padding
sha2/sha256_array.jinc     absorb from a fixed-length array (instance file)
sha2/sha512_k.jinc         SHA-512 round constants, shared by its kernels
sha2/sha512_compress.jinc  SHA-512 compression kernel (scalar)
sha2/sha512.jinc           SHA-384/512/512-224/512-256 values, buffering, padding
sha2/sha512_array.jinc     absorb from a fixed-length array (instance file)
sha2/hmac.jinc             HMAC over SHA-256 and SHA-512
sha2/mgf1.jinc             MGF1 over SHA-256 and SHA-512 (instance file)
sha2/sha256_x8.jinc        8-way SHA-224/256: initial values, padding, output
sha2/sha256_x8_array.jinc  8-way absorb of packed fixed-length arrays (instance file)
sha2/sha256_x8_compress.jinc 8-way SHA-256 compression kernel (scalar)
sha2/sha512_x4.jinc        4-way SHA-384/512/512-224/512-256: initial values, padding, output
sha2/sha512_x4_array.jinc  4-way absorb of packed fixed-length arrays (instance file)
sha2/sha512_x4_compress.jinc 4-way SHA-512 compression kernel (scalar)
x86_64/word.jinc           byte reversal, x86-64 instructions
aarch64/word.jinc          byte reversal, AArch64 instructions (owns the contract)
```

A kernel is the part a vector or crypto-extension variant replaces: the
Keccak permutation and the two SHA-2 compression functions. Everything
above the kernels (sponge, buffering, padding, HMAC, MGF1) is shared source
for every target and variant.

| Variant | Target | Kernels | State |
|---|---|---|---|
| `scalar` | x86-64, AArch64 | the `*_compress.jinc` and `keccakf1600*.jinc` kernels in this directory | implemented |
| `aarch64/scalar` | AArch64 | single-way Keccak with the 25 lanes in registers | implemented, `keccak/aarch64/scalar/` |
| `avx2` | x86-64 | 4-way Keccak, 8-way SHA-256, 4-way SHA-512 | planned |
| `shani` | x86-64 | single-stream SHA-256 | planned |
| `sha3` | AArch64 | NEON Keccak with EOR3/RAX1/XAR/BCAX | planned |
| `sha2` | AArch64 | SHA256H/H2/SU0/SU1, SHA512H/H2/SU0/SU1 | planned |

Variants live in `keccak/<arch>/<variant>/` and `sha2/<arch>/<variant>/` and
provide the entry points of the scalar kernel they replace, with the same
contracts, so the build selects a variant through include roots only.

A variant's required CPU features are a caller obligation: the build or the
run-time dispatch must select a variant only on CPUs that have them. The
kernels do not check.

## Building against these files

Six include roots:

| Root | Points at | Provides |
|---|---|---|
| `Hash` | `src/jasmin/hash` | everything below |
| `HashWord` | `src/jasmin/hash/<arch>` (`x86_64`, `aarch64`) | `word.jinc` |
| `KeccakKernel` | `src/jasmin/hash/keccak` or a single-way variant directory | `keccakf1600.jinc` |
| `KeccakKernelX` | `src/jasmin/hash/keccak` or a multi-way variant directory | `keccakf1600_x4.jinc` |
| `Sha2Kernel` | `src/jasmin/hash/sha2` or a single-way variant directory | `sha256_compress.jinc`, `sha512_compress.jinc` |
| `Sha2KernelX` | `src/jasmin/hash/sha2` or a multi-way variant directory | `sha256_x8_compress.jinc`, `sha512_x4_compress.jinc` |

Single-way and multi-way kernels have separate roots so that a target can
combine, for example, SHA-NI for single hashes with AVX2 for batches.

```sh
jasminc -arch armv8a -I Hash=src/jasmin/hash -I HashWord=src/jasmin/hash/aarch64 \
        -I KeccakKernel=src/jasmin/hash/keccak/aarch64/scalar \
        -I KeccakKernelX=src/jasmin/hash/keccak \
        -I Sha2Kernel=src/jasmin/hash/sha2 -I Sha2KernelX=src/jasmin/hash/sha2 ...

jasminc -arch x86-64 -I Hash=src/jasmin/hash -I HashWord=src/jasmin/hash/x86_64 \
        -I KeccakKernel=src/jasmin/hash/keccak \
        -I KeccakKernelX=src/jasmin/hash/keccak \
        -I Sha2Kernel=src/jasmin/hash/sha2 -I Sha2KernelX=src/jasmin/hash/sha2 ...
```

```
from Hash require "keccak/sponge.jinc"
from Hash require "sha2/sha256.jinc"
```

`tests/hash/Makefile` shows the complete invocation for both targets.

## Conventions

These hold for every function below unless its entry says otherwise.

**Classification.** Message bytes, keys, seeds, hash states and outputs are
secret. Pointers, lengths, positions, rates, domain bytes and instance sizes
are public. No branch, loop bound or memory address depends on secret data.
The caller must keep every public argument public on its own call path.

**Lengths.** Byte lengths are `reg u64`. SHA-2 totals must stay below
`2^61` bytes so that the bit length fits the 64-bit length field (for
SHA-512, the high half of the 128-bit field is then `total >> 61`, which is
0). Callers in this project stay far below that.

**Memory.** A `reg u64` pointer names caller memory of at least the stated
length. It is read or written only within that length. No alignment is
required. Input and output memory must not overlap unless an entry says so.

**Speculation.** Every function that contains a loop or a branch takes the
misspeculation flag `ms` (from `#init_msf`) and returns it, and declares its
speculative type with `#[sct = ...]`. Callers pass pointers and lengths
that are public, not merely transient: protect export arguments with
`#protect` / `#protect_ptr` before passing them, and protect any value
reloaded from the stack (a `#spill` / `#unspill` pair makes it transient).
The functions here do the same where their own loop state crosses a kernel
call through the stack. The flag itself cannot go through the stack (a
reloaded value is not a flag), so every kernel takes `ms` and returns it;
kernels without a branch return it unchanged.

**Residue.** These functions clear nothing. Caller-owned states and buffers
keep secret-derived data until the caller clears them. Function-local stack
also keeps secret-derived data on return:

| Function | Local stack residue on return |
|---|---|
| `_keccakf1600` (scalar kernel) | state after round 23 (25 lanes); C and D of round 24 |
| `_keccakf1600` (`aarch64/scalar`) | lanes (1, 4) to (3, 4) of round 24's θ input; lane (0, 0) of its χ output |
| `_sha256_compress*` (scalar kernel) | message schedule W_48 .. W_63 |
| `_sha512_compress*` (scalar kernel) | message schedule W_64 .. W_79 |
| `_sha3_*_mem`, `_shake*_mem` | the final sponge state |
| `_sha256_mem`, `_sha224_mem`, `_sha512*_mem`, `_sha384_mem` | the last padded block and the final chaining value |
| `_hmac_sha*_keyblock_mem` | H(K) for a key longer than one block |
| `__hmac_sha*_init` | the padded key blocks K0 ^ ipad and K0 ^ opad |
| `__hmac_sha*_finalize` | the inner digest |
| `_mgf1_sha*` | the padded seed message and the last chaining value |
| `_keccakf1600_x4` (scalar kernel) | instance 3's state, and the residue of `_keccakf1600` |
| `_sha256_x8_compress`, `_sha512_x4_compress` (scalar kernels) | instance 7's (4-way: 3's) chaining value, and the residue of the single-way kernel |

A function's residue includes the residue of every function it calls.
Clearing that stack is an obligation of the export that runs these
functions. No clearing mechanism is part of this directory or claimed by it.

**Array instances.** Jasmin arrays have static sizes, so functions that take
a byte array of caller-chosen length are written once and instantiated in a
namespace that fixes `HASH_ARRAY_LEN`:

```
from Hash require "keccak/sponge.jinc"

namespace HashN {
  param int HASH_ARRAY_LEN = 16;
  from Hash require "keccak/sponge_array.jinc"
  from Hash require "sha2/sha256_array.jinc"
}

st, pos, ms = HashN::_keccak_absorb_array(st, pos, rate, seed, ms);
```

The non-instance file of the same family must be required at top level
first. One namespace may instantiate several array files at the same length.

## Keccak (FIPS 202)

### State

`reg ptr u64[25] st`. Lane `(x, y)` of FIPS 202 section 3.1.2 is `st[x + 5*y]`;
bytes within a lane are little-endian, so byte `i` of the state string `S`
(section 3.1.3) is `st[:u8 i]`.

A sponge in progress is `(st, pos)` for a fixed `rate`:

| Phase | Meaning of `pos` | Range |
|---|---|---|
| absorbing | bytes of the current block already XORed into `st` | `0 <= pos < rate` |
| squeezing | bytes of the current permuted block already output | `0 <= pos <= rate` |

`rate` is a public byte count, a multiple of 8, at most 168:

| Function | rate | domain byte `ds` |
|---|---|---|
| SHA3-224 | 144 | `0x06` |
| SHA3-256 | 136 | `0x06` |
| SHA3-384 | 104 | `0x06` |
| SHA3-512 | 72  | `0x06` |
| SHAKE128 | 168 | `0x1f` |
| SHAKE256 | 136 | `0x1f` |

Rates are `1600 - 2d` bits (FIPS 202 sections 6.1, 6.2). The domain byte holds
the suffix `01` (SHA-3) or `1111` (SHAKE) followed by the first padding bit,
in the bit order of FIPS 202 appendix B.2.

### `keccak/keccakf1600.jinc`

```
fn _keccakf1600(reg mut ptr u64[25] st, reg u64 ms) -> reg ptr u64[25], reg u64
```

`st <- Keccak-p[1600, 24](st)` (FIPS 202 section 3.3, `Keccak-f[1600]`).

### `keccak/sponge.jinc`

```
inline fn __keccak_init(reg mut ptr u64[25] st) -> reg ptr u64[25]

fn _keccak_absorb_mem(reg mut ptr u64[25] st, reg u64 pos rate in inlen, reg u64 ms)
  -> reg ptr u64[25], reg u64, reg u64                      /* st, pos, ms */

fn _keccak_finalize(reg mut ptr u64[25] st, reg u64 pos rate ds, reg u64 ms)
  -> reg ptr u64[25], reg u64                                /* st, ms */

fn _keccak_squeeze_mem(reg mut ptr u64[25] st, reg u64 pos rate out outlen, reg u64 ms)
  -> reg ptr u64[25], reg u64, reg u64                      /* st, pos, ms */
```

- `__keccak_init` zeroes the state. Start absorbing with `pos = 0`.
- `_keccak_absorb_mem` XORs `inlen` bytes from `in` into the state from
  position `pos`, applying the permutation each time a block fills. It
  returns the new position. Any `inlen`, including 0.
- `_keccak_finalize` applies the domain byte (below `0x80`) and `pad10*1` at
  `pos` and permutes once. Squeezing then starts with `pos = 0`.
- `_keccak_squeeze_mem` writes `outlen` bytes to `out`, permuting first
  whenever `pos = rate`. Successive calls continue the output stream, so a
  squeeze may be split at any byte boundary.
- The state has no phase flag: absorbing after finalize is a caller error
  that nothing detects.

### `keccak/sponge_array.jinc` (array instance)

```
fn _keccak_absorb_array(reg mut ptr u64[25] st, reg u64 pos rate,
                        reg const ptr u8[HASH_ARRAY_LEN] in, reg u64 ms)
  -> reg ptr u64[25], reg u64, reg u64                      /* st, pos, ms */

fn _keccak_squeeze_array(reg mut ptr u8[HASH_ARRAY_LEN] out,
                         reg mut ptr u64[25] st, reg u64 pos rate, reg u64 ms)
  -> reg ptr u8[HASH_ARRAY_LEN], reg ptr u64[25], reg u64, reg u64
                                                    /* out, st, pos, ms */
```

The same contracts as the memory forms, with the whole array as input or
output.

### `keccak/fips202.jinc`

One-shot forms from memory, used for HashSLH-DSA pre-hashing and tests:

```
fn _sha3_224_mem(reg mut ptr u8[28] out, reg u64 in inlen, reg u64 ms) -> reg ptr u8[28], reg u64
fn _sha3_256_mem(reg mut ptr u8[32] out, reg u64 in inlen, reg u64 ms) -> reg ptr u8[32], reg u64
fn _sha3_384_mem(reg mut ptr u8[48] out, reg u64 in inlen, reg u64 ms) -> reg ptr u8[48], reg u64
fn _sha3_512_mem(reg mut ptr u8[64] out, reg u64 in inlen, reg u64 ms) -> reg ptr u8[64], reg u64
fn _shake128_mem(reg u64 out outlen in inlen, reg u64 ms) -> reg u64
fn _shake256_mem(reg u64 out outlen in inlen, reg u64 ms) -> reg u64
```

## SHA-2 (FIPS 180-4)

### State

A hash in progress is three caller-held objects:

| Object | SHA-224/256 | SHA-384/512, SHA-512/t |
|---|---|---|
| chaining value `h` | `reg ptr u32[8]` | `reg ptr u64[8]` |
| block buffer `buf` | `reg ptr u8[64]` | `reg ptr u8[128]` |
| total `total` | `reg u64` bytes absorbed so far | same |

`h[i]` is `H_i` of FIPS 180-4 section 6.2 / 6.4 as a native word. `buf`
holds the `total mod blocksize` bytes not yet compressed, at its start.
`total` counts every byte absorbed, including those already compressed, so
a caller that compresses a block itself (for example a precomputed state)
continues with `total` equal to the bytes that state covers.

### `sha2/sha256_compress.jinc` (kernel)

```
fn _sha256_compress(reg mut ptr u32[8] h, reg const ptr u8[64] block, reg u64 ms)
  -> reg ptr u32[8], reg u64
fn _sha256_compress_ptr(reg mut ptr u32[8] h, reg u64 p, reg u64 ms)
  -> reg ptr u32[8], reg u64
```

`h <- compress(h, M)` for one 64-byte block (FIPS 180-4 section 6.2.2,
steps 1 to 4), from an array or from 64 bytes of memory. `ms` passes
through unchanged. The SHA-256 functions of FIPS 205 section 11.2 hash
`PK.seed || toByte(0, 64 - n)` as their first block: the caller computes
that state once, copies it per call, and continues with `total = 64`. The
SHA-512 functions (`H`, `T_l` of security categories 3 and 5) do the same
with `PK.seed || toByte(0, 128 - n)` and `total = 128`.

### `sha2/sha256.jinc`

```
inline fn __sha256_init(reg mut ptr u32[8] h) -> reg ptr u32[8]      /* FIPS 180-4 5.3.3 */
inline fn __sha224_init(reg mut ptr u32[8] h) -> reg ptr u32[8]      /* FIPS 180-4 5.3.2 */

fn _sha256_absorb_mem(reg mut ptr u32[8] h, reg mut ptr u8[64] buf, reg u64 total in inlen,
                      reg u64 ms)
  -> reg ptr u32[8], reg ptr u8[64], reg u64, reg u64      /* h, buf, total, ms */

fn _sha256_finalize(reg mut ptr u8[32] out, reg mut ptr u32[8] h, reg mut ptr u8[64] buf,
                    reg u64 total, reg u64 ms)
  -> reg ptr u8[32], reg ptr u32[8], reg ptr u8[64], reg u64  /* out, h, buf, ms */

fn _sha256_mem(reg mut ptr u8[32] out, reg u64 in inlen, reg u64 ms) -> reg ptr u8[32], reg u64
fn _sha224_mem(reg mut ptr u8[32] out, reg u64 in inlen, reg u64 ms) -> reg ptr u8[32], reg u64
```

- `_sha256_absorb_mem` appends `inlen` bytes from `in`.
- `_sha256_finalize` pads (section 5.1.1), compresses the final block or two,
  and writes `H_0 .. H_7` big-endian to `out`. SHA-224 output is `out[0:28]`.
  `h` and `buf` are left holding final-state data and must be reinitialised
  before reuse.
- `_sha224_mem` writes all 32 bytes of `out`; the first 28 are the SHA-224
  digest and the last 4 the rest of the final chaining value, which is not
  part of the digest and must not be published with it.

### `sha2/sha256_array.jinc` (array instance)

```
fn _sha256_absorb_array(reg mut ptr u32[8] h, reg mut ptr u8[64] buf, reg u64 total,
                        reg const ptr u8[HASH_ARRAY_LEN] in, reg u64 ms)
  -> reg ptr u32[8], reg ptr u8[64], reg u64, reg u64      /* h, buf, total, ms */
```

### `sha2/sha512_compress.jinc`, `sha2/sha512.jinc`, `sha2/sha512_array.jinc`

The SHA-256 interface with `u64[8]` states, `u8[128]` buffers and a
`u8[64]` digest:

```
fn _sha512_compress(reg mut ptr u64[8] h, reg const ptr u8[128] block, reg u64 ms)
  -> reg ptr u64[8], reg u64
fn _sha512_compress_ptr(reg mut ptr u64[8] h, reg u64 p, reg u64 ms)
  -> reg ptr u64[8], reg u64
inline fn __sha512_init / __sha384_init / __sha512_224_init / __sha512_256_init
                                    (reg mut ptr u64[8] h) -> reg ptr u64[8]  /* 5.3.4 - 5.3.6 */
fn _sha512_absorb_mem(...)   fn _sha512_absorb_array(...)   fn _sha512_finalize(...)
fn _sha512_mem / _sha384_mem / _sha512_224_mem / _sha512_256_mem
        (reg mut ptr u8[64] out, reg u64 in inlen, reg u64 ms) -> reg ptr u8[64], reg u64
```

Every one-shot and finalize function writes all 64 bytes of `out`.
Truncated digests are prefixes: SHA-384 48 bytes, SHA-512/256 32,
SHA-512/224 28. The remaining bytes are the rest of the final chaining
value; they are not part of the digest and must not be published with it.

### `sha2/hmac.jinc`

HMAC of FIPS 198-1, split so the inner hash uses the ordinary absorb
functions:

```
fn _hmac_sha256_keyblock_mem(reg mut ptr u8[64] k0, reg u64 key keylen, reg u64 ms)
  -> reg ptr u8[64], reg u64
inline fn __hmac_sha256_init(stack u32[8] inner outer, reg const ptr u8[64] k0, reg u64 ms)
  -> stack u32[8], stack u32[8], reg u64
inline fn __hmac_sha256_finalize(stack u8[32] out, reg mut ptr u32[8] inner,
                                 reg mut ptr u8[64] buf, reg u64 total,
                                 stack u32[8] outer, reg u64 ms)
  -> stack u8[32], reg ptr u32[8], reg ptr u8[64], reg u64
```

and the same with `sha512`, `u64[8]`, `u8[128]` and a `u8[64]` tag.

1. Form `K0` (FIPS 198-1 section 4, steps 1 to 3): the key padded with
   zeros to one block, or its digest padded when it is longer than a block.
   `_hmac_sha256_keyblock_mem` does this from memory. A caller whose key is a
   short array (FIPS 205 `SK.prf`, `n <= 32` bytes) writes `K0` itself.
2. `__hmac_sha256_init` stores the states after compressing `K0 ^ ipad` and
   `K0 ^ opad` into `inner` and `outer`, which must be the caller's stack
   arrays (see the function's comment for why; `out` and `outer` of the
   finalize function likewise).
3. Absorb the message into `inner` with `buf` empty and `total = 64`.
4. `__hmac_sha256_finalize` writes the full tag and only reads `outer`, so a
   caller may keep `outer` for further messages under the same key. FIPS 205
   truncates the tag to `n` bytes.

### `sha2/mgf1.jinc` (array instance)

Instantiated with `MGF1_SEED_LEN` and `MGF1_OUT_LEN`. Block `c` of `T`
hashes the seed followed by the four-byte counter `I2OSP(c, 4)`; FIPS 205
needs at most 49 output bytes.

```
fn _mgf1_sha256(reg mut ptr u8[MGF1_OUT_LEN] out, reg const ptr u8[MGF1_SEED_LEN] seed,
                reg u64 ms) -> reg ptr u8[MGF1_OUT_LEN], reg u64
fn _mgf1_sha512(...)    /* same shape */
```

`out = T[0 : MGF1_OUT_LEN]`, `T = Hash(seed || I2OSP(0, 4)) || Hash(seed || I2OSP(1, 4)) || ...`
(RFC 8017, appendix B.2.1). FIPS 205 section 11.2 uses it for `H_msg` with
`seed = R || PK.seed || Hash(R || PK.seed || PK.root || M)`.

## Multi-way interfaces

Batched forms run independent hashes of equal shape together: WOTS+ chains,
FORS leaves and tree nodes. Each multi-way function computes exactly what
the single-way functions compute on each instance separately.

| Interface | Instances | State layout | State |
|---|---|---|---|
| Keccak x4 | 4 | `reg ptr u64[100]`: lane `j` of instance `k` at `4*j + k` | implemented |
| SHA-256 x8 | 8 | `reg ptr u32[64]`: word `j` of instance `k` at `8*j + k` | implemented |
| SHA-512 x4 | 4 | `reg ptr u64[32]`: word `j` of instance `k` at `4*j + k` | implemented |

Interleaving word `j` of all instances is the layout in which one vector
register holds that word of every instance. Instances share `pos`, `rate`
and `total`, because their inputs have the same shape.

### `keccak/keccakf1600_x4.jinc` (kernel), `keccak/sponge_x4.jinc`

```
fn _keccakf1600_x4(reg mut ptr u64[100] st, reg u64 ms) -> reg ptr u64[100], reg u64

inline fn __keccak_x4_init(reg mut ptr u64[100] st) -> reg ptr u64[100]
fn _keccak_x4_finalize(reg mut ptr u64[100] st, reg u64 pos rate ds, reg u64 ms)
  -> reg ptr u64[100], reg u64
```

### `keccak/sponge_x4_array.jinc` (array instance)

```
fn _keccak_x4_absorb_array(reg mut ptr u64[100] st, reg u64 pos rate,
                           reg const ptr u8[HASH_ARRAY_LEN] in0 in1 in2 in3, reg u64 ms)
  -> reg ptr u64[100], reg u64, reg u64                     /* st, pos, ms */
fn _keccak_x4_squeeze_array(reg mut ptr u8[HASH_ARRAY_LEN] out0 out1 out2 out3,
                            reg mut ptr u64[100] st, reg u64 pos rate, reg u64 ms)
  -> four reg ptr u8[HASH_ARRAY_LEN], reg ptr u64[100], reg u64, reg u64
```

The single-way contracts of `sponge.jinc` and `sponge_array.jinc` hold per
instance. Instance `k`'s byte `b` is `st[:u8 32*(b/8) + 8*k + b%8]`. The same
array may be passed for several instances (a shared prefix such as
`PK.seed`).

### Multi-way SHA-2: `sha2/sha256_x8.jinc`, `sha2/sha512_x4.jinc`

```
fn _sha256_x8_compress(reg mut ptr u32[64] h8, reg const ptr u8[512] blocks, reg u64 ms)
  -> reg ptr u32[64], reg u64                      /* block k at bytes 64k .. 64k+63 */
inline fn __sha256_x8_init / __sha224_x8_init(reg mut ptr u32[64] h8) -> reg ptr u32[64]
fn _sha256_x8_absorb_array(reg mut ptr u32[64] h8, reg mut ptr u8[512] buf, reg u64 total,
                           reg const ptr u8[8 * HASH_ARRAY_LEN] in, reg u64 ms)
  -> reg ptr u32[64], reg ptr u8[512], reg u64, reg u64
fn _sha256_x8_finalize(reg mut ptr u8[256] out, reg mut ptr u32[64] h8,
                       reg mut ptr u8[512] buf, reg u64 total, reg u64 ms)
  -> reg ptr u8[256], reg ptr u32[64], reg ptr u8[512], reg u64
```

and the 4-way SHA-512 family with `u64[32]` states, `u8[512]` buffers
(4 x 128), `u8[256]` outputs (4 x 64) and `__sha512_x4_init`,
`__sha384_x4_init`, `__sha512_224_x4_init`, `__sha512_256_x4_init`.

- Instance `k`'s pending block is `buf[64k .. 64k+63]` (SHA-512:
  `buf[128k .. 128k+127]`); its output is `out[32k ..]` (SHA-512: `out[64k ..]`),
  with truncated digests as prefixes as in the single-way functions.
- Array inputs are packed: instance `k`'s array is
  `in[k*HASH_ARRAY_LEN .. (k+1)*HASH_ARRAY_LEN - 1]`. One pointer serves every
  instance, so a multi-way loop carries one input pointer, not one per
  instance.
- `total` is shared, so each instance's FIPS 205 precomputed `PK.seed` state
  is the same 8 words broadcast into the 8 lanes, continued with `total = 64`.

## Kernel notes

Observations about emitted code that source choices rest on. They were made
with the pinned toolchain (`toolchain/jasmin/PIN`, `SERIES` and
`PATCHES.md`) and are rechecked when the compiler or a kernel changes. A kernel is a local
function, so its code in the test assembly runs from its label to the first
`ret`; for example, the registers the scalar Keccak kernel names:

    make -C tests/hash asm
    sed -n '/^\.*L_keccakf1600\$1:/,/^[[:space:]]*ret/p' build/hash/*/hash_test.s |
      grep -oE '%[a-z0-9]+|\<[xw][0-9]+\>' | sort -u

The label is `.L_keccakf1600$1` in ELF output and `L_keccakf1600$1` in
Mach-O output; the pattern accepts both.

- **Keccak, x86-64 scalar.** C and D live in stack scratch, and the emitted
  kernel names ten general-purpose registers (rax, rbx, rcx, rdx, rsi, rdi,
  r8 to r11).
- **Keccak, AArch64.** The `aarch64/scalar` kernel keeps the 25 lanes in
  registers. 28 are allocatable (x0 to x17 and x19 to x28; the pinned
  toolchain never allocates x29, the frame pointer), and the kernel names
  all of them: the misspeculation flag and two temporaries take the rest.
  Each round parks four lanes in the stack during θ and one during χ, so
  besides the round constant it makes five stores and five loads. The
  emitted kernel has no register moves, and ρ and π are 24 rotates per
  round (576 `ror` in all).
- **Values across kernel calls.** Kernels are local functions. The
  compiler's register allocation covers caller and callee together: a value
  live across a call keeps a register the callee does not write, or the
  program is rejected, so no calling convention needs to be followed. Code
  here moves a value through the stack (`#spill` / `#unspill`) where it
  crosses a call, and `jasmin-ct --sct` treats a reloaded value as
  transient, so it is protected (`#protect`, `#protect_ptr`) before use as
  an address, bound or length. A kernel's own loop may keep its state in
  registers instead.
