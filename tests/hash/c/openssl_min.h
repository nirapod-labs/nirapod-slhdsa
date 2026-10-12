/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The few libcrypto (OpenSSL 3) entry points the differential tests call,
 * declared here so the harness builds against the shared library alone,
 * without development headers. Signatures are those of OpenSSL 3.x
 * (include/openssl/evp.h, include/openssl/hmac.h); the library is the
 * independent oracle, never part of the code under test.
 */

#ifndef NIRAPOD_HASH_TEST_OPENSSL_MIN_H
#define NIRAPOD_HASH_TEST_OPENSSL_MIN_H

#include <stddef.h>

typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct engine_st ENGINE;

const EVP_MD *EVP_get_digestbyname(const char *name);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md, size_t len);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *data, size_t data_len,
                    unsigned char *md, unsigned int *md_len);
unsigned long OpenSSL_version_num(void);
const char *OpenSSL_version(int type);

#endif
