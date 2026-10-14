/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * tables.c
 * ========
 *
 * Parameter-set sizes and pre-hash identifiers shared by all drivers. These
 * are test-side copies, written from the standard and not from any
 * implementation, so a size or OID mistake in an implementation shows up as
 * a mismatch instead of being inherited.
 */

#include <string.h>

#include "impl.h"

/* FIPS 205 Table 2; pk = 2n, sk = 4n (Figures 15, 16). */
const slh_set slh_sets[SLH_SET_COUNT] = {
    { "SLH-DSA-SHA2-128s",  16,  32,  64,  7856 },
    { "SLH-DSA-SHAKE-128s", 16,  32,  64,  7856 },
    { "SLH-DSA-SHA2-128f",  16,  32,  64, 17088 },
    { "SLH-DSA-SHAKE-128f", 16,  32,  64, 17088 },
    { "SLH-DSA-SHA2-192s",  24,  48,  96, 16224 },
    { "SLH-DSA-SHAKE-192s", 24,  48,  96, 16224 },
    { "SLH-DSA-SHA2-192f",  24,  48,  96, 35664 },
    { "SLH-DSA-SHAKE-192f", 24,  48,  96, 35664 },
    { "SLH-DSA-SHA2-256s",  32,  64, 128, 29792 },
    { "SLH-DSA-SHAKE-256s", 32,  64, 128, 29792 },
    { "SLH-DSA-SHA2-256f",  32,  64, 128, 49856 },
    { "SLH-DSA-SHAKE-256f", 32,  64, 128, 49856 },
};

/*
 * OIDs are 2.16.840.1.101.3.4.2.x (NIST Computer Security Objects
 * Register), DER-encoded as 06 09 60 86 48 01 65 03 04 02 x. Digest
 * lengths are those of FIPS 180-4 and FIPS 202; for the two XOFs FIPS 205
 * section 10.2.2 fixes 256 bits (SHAKE128) and 512 bits (SHAKE256).
 */
#define NIST_HASH_OID(x) { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, (x) }

const slh_ph_info slh_ph_table[PH_COUNT] = {
    [PH_NONE]         = { "none",         { 0 },                0 },
    [PH_SHA2_256]     = { "SHA2-256",     NIST_HASH_OID(0x01), 32 },
    [PH_SHA2_384]     = { "SHA2-384",     NIST_HASH_OID(0x02), 48 },
    [PH_SHA2_512]     = { "SHA2-512",     NIST_HASH_OID(0x03), 64 },
    [PH_SHA2_224]     = { "SHA2-224",     NIST_HASH_OID(0x04), 28 },
    [PH_SHA2_512_224] = { "SHA2-512/224", NIST_HASH_OID(0x05), 28 },
    [PH_SHA2_512_256] = { "SHA2-512/256", NIST_HASH_OID(0x06), 32 },
    [PH_SHA3_224]     = { "SHA3-224",     NIST_HASH_OID(0x07), 28 },
    [PH_SHA3_256]     = { "SHA3-256",     NIST_HASH_OID(0x08), 32 },
    [PH_SHA3_384]     = { "SHA3-384",     NIST_HASH_OID(0x09), 48 },
    [PH_SHA3_512]     = { "SHA3-512",     NIST_HASH_OID(0x0a), 64 },
    [PH_SHAKE_128]    = { "SHAKE-128",    NIST_HASH_OID(0x0b), 32 },
    [PH_SHAKE_256]    = { "SHAKE-256",    NIST_HASH_OID(0x0c), 64 },
};

/*
 * Second derivation of the sizes, from the tree parameters of FIPS 205
 * Table 2 (n, h, d, a, k; lg_w = 4 for every set, so len = 2n + 3 by
 * Equations 5.1-5.4): pk = 2n, sk = 4n, sig = (1 + k(1 + a) + h + d*len)n
 * (Figure 17). A typo in either table makes the drivers stop at start-up.
 */
int slh_tables_check(void)
{
    static const struct { size_t n, h, d, a, k; } t[SLH_SET_COUNT] = {
        { 16, 63, 7, 12, 14 }, { 16, 63, 7, 12, 14 }, { 16, 66, 22, 6, 33 },
        { 16, 66, 22, 6, 33 }, { 24, 63, 7, 14, 17 }, { 24, 63, 7, 14, 17 },
        { 24, 66, 22, 8, 33 }, { 24, 66, 22, 8, 33 }, { 32, 64, 8, 14, 22 },
        { 32, 64, 8, 14, 22 }, { 32, 68, 17, 9, 35 }, { 32, 68, 17, 9, 35 },
    };

    for (int i = 0; i < SLH_SET_COUNT; i++) {
        size_t n = t[i].n, len = 2 * n + 3;
        size_t sig = (1 + t[i].k * (1 + t[i].a) + t[i].h + t[i].d * len) * n;
        if (slh_sets[i].n != n || slh_sets[i].pk_bytes != 2 * n ||
            slh_sets[i].sk_bytes != 4 * n || slh_sets[i].sig_bytes != sig)
            return -1;
    }
    return 0;
}

int slh_set_index(const char *name)
{
    for (int i = 0; i < SLH_SET_COUNT; i++)
        if (strcmp(slh_sets[i].name, name) == 0)
            return i;
    return -1;
}

int slh_ph_index(const char *name)
{
    if (strcmp(name, "pure") == 0)
        return PH_NONE;
    for (int i = 0; i < PH_COUNT; i++)
        if (strcmp(slh_ph_table[i].name, name) == 0)
            return i;
    return -1;
}
