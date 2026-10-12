/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * C prototypes of the Jasmin test exports in tests/hash/jasmin/. Each one
 * runs one hash primitive between C memory and the primitive's Jasmin
 * calling form; the .jinc files in tests/hash/jasmin own the exact behaviour.
 *
 * State layouts match the Jasmin side:
 *
 *     Keccak     uint64_t st[25], lane (x, y) at x + 5y, host byte order
 *     SHA-256    uint32_t h[8] chaining value, uint8_t buf[64] pending block
 *     SHA-512    uint64_t h[8] chaining value, uint8_t buf[128] pending block
 *
 * Both test hosts are little-endian, which these layouts assume.
 */

#ifndef NIRAPOD_HASH_TEST_EXPORTS_H
#define NIRAPOD_HASH_TEST_EXPORTS_H

#include <stdint.h>

#define HT(name) nirapod_slhdsa_hashtest_##name

/* Keccak */
void HT(keccakf1600)(uint64_t st[25]);
uint64_t HT(keccak_absorb)(uint64_t st[25], uint64_t pos, uint64_t rate,
                           const uint8_t *in, uint64_t inlen);
void HT(keccak_finalize)(uint64_t st[25], uint64_t pos, uint64_t rate, uint64_t ds);
uint64_t HT(keccak_squeeze)(uint64_t st[25], uint64_t pos, uint64_t rate,
                            uint8_t *out, uint64_t outlen);
void HT(sha3_224)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(sha3_256)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(sha3_384)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(sha3_512)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(shake128)(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen);
void HT(shake256)(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen);

/* SHA-2 one-shot: each writes exactly its digest length to out. */
void HT(sha224)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(sha256)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(sha384)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(sha512)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(sha512_224)(uint8_t *out, const uint8_t *in, uint64_t inlen);
void HT(sha512_256)(uint8_t *out, const uint8_t *in, uint64_t inlen);

/* SHA-2 incremental; finalize writes the full 32- or 64-byte output. */
void HT(sha256_init)(uint32_t h[8]);
void HT(sha224_init)(uint32_t h[8]);
uint64_t HT(sha256_absorb)(uint32_t h[8], uint8_t buf[64], uint64_t total,
                           const uint8_t *in, uint64_t inlen);
void HT(sha256_finalize)(uint8_t out[32], uint32_t h[8], uint8_t buf[64], uint64_t total);
void HT(sha256_compress)(uint32_t h[8], const uint8_t block[64]);
void HT(sha256_compress_blocks)(uint32_t h[8], const uint8_t *blocks, uint64_t n);

void HT(sha512_init)(uint64_t h[8]);
void HT(sha384_init)(uint64_t h[8]);
void HT(sha512_224_init)(uint64_t h[8]);
void HT(sha512_256_init)(uint64_t h[8]);
uint64_t HT(sha512_absorb)(uint64_t h[8], uint8_t buf[128], uint64_t total,
                           const uint8_t *in, uint64_t inlen);
void HT(sha512_finalize)(uint8_t out[64], uint64_t h[8], uint8_t buf[128], uint64_t total);
void HT(sha512_compress)(uint64_t h[8], const uint8_t block[128]);
void HT(sha512_compress_blocks)(uint64_t h[8], const uint8_t *blocks, uint64_t n);

/* HMAC: full-length tag (32 or 64 bytes). */
void HT(hmac_sha256)(uint8_t out[32], const uint8_t *key, uint64_t keylen,
                     const uint8_t *msg, uint64_t msglen);
void HT(hmac_sha512)(uint8_t out[64], const uint8_t *key, uint64_t keylen,
                     const uint8_t *msg, uint64_t msglen);

/* Array instances, one per tested length L: in and out hold exactly L bytes. */
#define HT_ARRAY_PROTOS(L)                                                        \
  uint64_t HT(keccak_absorb_array_##L)(uint64_t st[25], uint64_t pos,             \
                                       uint64_t rate, const uint8_t *in);         \
  uint64_t HT(keccak_squeeze_array_##L)(uint8_t *out, uint64_t st[25],            \
                                        uint64_t pos, uint64_t rate);             \
  uint64_t HT(sha256_absorb_array_##L)(uint32_t h[8], uint8_t buf[64],            \
                                       uint64_t total, const uint8_t *in);        \
  uint64_t HT(sha512_absorb_array_##L)(uint64_t h[8], uint8_t buf[128],           \
                                       uint64_t total, const uint8_t *in);

HT_ARRAY_PROTOS(1)
HT_ARRAY_PROTOS(7)
HT_ARRAY_PROTOS(16)
HT_ARRAY_PROTOS(22)
HT_ARRAY_PROTOS(32)
HT_ARRAY_PROTOS(64)
HT_ARRAY_PROTOS(65)
HT_ARRAY_PROTOS(129)
HT_ARRAY_PROTOS(200)

/* 4-way Keccak: st is uint64_t[100], lane j of instance k at 4j + k. */
void HT(keccak_x4_init)(uint64_t st[100]);
void HT(keccakf1600_x4)(uint64_t st[100]);
void HT(keccak_x4_finalize)(uint64_t st[100], uint64_t pos, uint64_t rate, uint64_t ds);

/* 4-way array instances: in and out hold four L-byte arrays back to back. */
#define HT_X4_PROTOS(L)                                                           \
  uint64_t HT(keccak_x4_absorb_array_##L)(uint64_t st[100], uint64_t pos,         \
                                          uint64_t rate, const uint8_t *in);      \
  uint64_t HT(keccak_x4_squeeze_array_##L)(uint8_t *out, uint64_t st[100],        \
                                           uint64_t pos, uint64_t rate);

HT_X4_PROTOS(1)
HT_X4_PROTOS(7)
HT_X4_PROTOS(16)
HT_X4_PROTOS(22)
HT_X4_PROTOS(32)
HT_X4_PROTOS(64)
HT_X4_PROTOS(65)
HT_X4_PROTOS(129)
HT_X4_PROTOS(200)

/*
 * Multi-way SHA-2. SHA-256 x8: h is uint32_t[64] (H_j of instance k at
 * 8j + k), buf is 8 x 64 bytes, out 8 x 32 bytes. SHA-512 x4: h is
 * uint64_t[32] (4j + k), buf 4 x 128 bytes, out 4 x 64 bytes. Array inputs
 * hold the instances' L-byte arrays back to back.
 */
void HT(sha256_x8_init)(uint32_t h[64]);
void HT(sha224_x8_init)(uint32_t h[64]);
void HT(sha256_x8_compress)(uint32_t h[64], const uint8_t blocks[512]);
void HT(sha256_x8_finalize)(uint8_t out[256], uint32_t h[64], uint8_t buf[512], uint64_t total);
void HT(sha512_x4_init)(uint64_t h[32]);
void HT(sha384_x4_init)(uint64_t h[32]);
void HT(sha512_224_x4_init)(uint64_t h[32]);
void HT(sha512_256_x4_init)(uint64_t h[32]);
void HT(sha512_x4_compress)(uint64_t h[32], const uint8_t blocks[512]);
void HT(sha512_x4_finalize)(uint8_t out[256], uint64_t h[32], uint8_t buf[512], uint64_t total);

#define HT_SHAX_PROTOS(L)                                                         \
  uint64_t HT(sha256_x8_absorb_array_##L)(uint32_t h[64], uint8_t buf[512],       \
                                          uint64_t total, const uint8_t *in);     \
  uint64_t HT(sha512_x4_absorb_array_##L)(uint64_t h[32], uint8_t buf[512],       \
                                          uint64_t total, const uint8_t *in);

HT_SHAX_PROTOS(1)
HT_SHAX_PROTOS(7)
HT_SHAX_PROTOS(16)
HT_SHAX_PROTOS(22)
HT_SHAX_PROTOS(32)
HT_SHAX_PROTOS(64)
HT_SHAX_PROTOS(65)
HT_SHAX_PROTOS(129)
HT_SHAX_PROTOS(200)

/* MGF1 instances named <hash>_<seed length>_<output length>. */
void HT(mgf1_sha256_64_30)(uint8_t *out, const uint8_t *seed);
void HT(mgf1_sha256_64_34)(uint8_t *out, const uint8_t *seed);
void HT(mgf1_sha512_112_39)(uint8_t *out, const uint8_t *seed);
void HT(mgf1_sha512_112_42)(uint8_t *out, const uint8_t *seed);
void HT(mgf1_sha512_128_47)(uint8_t *out, const uint8_t *seed);
void HT(mgf1_sha512_128_49)(uint8_t *out, const uint8_t *seed);

#endif
