/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * hash_test.c
 * ===========
 *
 * Native validation of the Jasmin hash primitives through their test
 * exports (hash_test_exports.h). Two modes:
 *
 *     hash_test cavp <dir>
 *         NIST CAVP byte-oriented response files: ShortMsg, LongMsg and
 *         Monte Carlo for SHA-224 .. SHA-512/256, SHA3-224 .. SHA3-512,
 *         SHAKE128 and SHAKE256; VariableOut for SHAKE; HMAC for the
 *         SHA-256 and SHA-512 sections. Also the published known answers
 *         for Keccak-f[1600] alone.
 *
 *     hash_test diff <seed> <iterations>
 *         Seeded random comparison with libcrypto (OpenSSL 3) as an
 *         independent oracle: one-shot, incremental with random split
 *         points, the fixed-length array instances, HMAC with all key
 *         length classes, MGF1 (composed here from libcrypto SHA-2), and
 *         the multi-way forms: 4-way Keccak, 8-way SHA-256, 4-way SHA-512.
 *         SHA-2 finalize, single-way and multi-way, with totals no message
 *         reaches is checked against padding laid out here.
 *
 * What a PASS establishes: the exported production code paths produced
 * the expected bytes on the cases listed in the summary, on this host.
 * It is not a proof and says nothing about timing.
 *
 * Fail-closed: a missing or unreadable file, a file with no test cases, a
 * parse error, an oracle error or any mismatch makes the exit status
 * non-zero. Every mismatch prints the case needed to reproduce it.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_test_exports.h"
#include "openssl_min.h"

/* ------------------------------------------------------------------ */
/* Bookkeeping                                                        */

static unsigned long g_pass, g_fail;

static void hexdump(const char *label, const uint8_t *p, size_t n)
{
  size_t i;

  fprintf(stderr, "  %s (%zu bytes): ", label, n);
  for (i = 0; i < n; i++)
    fprintf(stderr, "%02x", p[i]);
  fprintf(stderr, "\n");
}

static int check(const char *what, const uint8_t *got, const uint8_t *want, size_t n)
{
  if (memcmp(got, want, n) == 0) {
    g_pass++;
    return 1;
  }
  g_fail++;
  fprintf(stderr, "FAIL %s\n", what);
  hexdump("got ", got, n);
  hexdump("want", want, n);
  return 0;
}

static void die(const char *msg, const char *detail)
{
  fprintf(stderr, "error: %s%s%s\n", msg, detail ? ": " : "", detail ? detail : "");
  exit(2);
}

static void *xmalloc(size_t n)
{
  void *p = malloc(n ? n : 1);
  if (!p)
    die("out of memory", NULL);
  return p;
}

/* ------------------------------------------------------------------ */
/* Algorithms under test                                               */

typedef void (*digest_fn)(uint8_t *out, const uint8_t *in, uint64_t inlen);
typedef void (*xof_fn)(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen);

struct digest {
  const char *cavp;      /* CAVP file prefix */
  const char *ossl;      /* libcrypto name */
  digest_fn fn;
  size_t len;            /* digest bytes */
  int sha3;              /* 1: SHA-3 Monte Carlo, 0: SHA-2 Monte Carlo */
};

static const struct digest DIGESTS[] = {
  { "SHA224",     "SHA224",     HT(sha224),     28, 0 },
  { "SHA256",     "SHA256",     HT(sha256),     32, 0 },
  { "SHA384",     "SHA384",     HT(sha384),     48, 0 },
  { "SHA512",     "SHA512",     HT(sha512),     64, 0 },
  { "SHA512_224", "SHA512-224", HT(sha512_224), 28, 0 },
  { "SHA512_256", "SHA512-256", HT(sha512_256), 32, 0 },
  { "SHA3_224",   "SHA3-224",   HT(sha3_224),   28, 1 },
  { "SHA3_256",   "SHA3-256",   HT(sha3_256),   32, 1 },
  { "SHA3_384",   "SHA3-384",   HT(sha3_384),   48, 1 },
  { "SHA3_512",   "SHA3-512",   HT(sha3_512),   64, 1 },
};

struct xof {
  const char *cavp;
  const char *ossl;
  xof_fn fn;
  uint64_t rate;
};

static const struct xof XOFS[] = {
  { "SHAKE128", "SHAKE128", HT(shake128), 168 },
  { "SHAKE256", "SHAKE256", HT(shake256), 136 },
};

/* ------------------------------------------------------------------ */
/* Oracle (libcrypto)                                                  */

static void ossl_digest(const char *name, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen,
                        int xof)
{
  const EVP_MD *md = EVP_get_digestbyname(name);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned int n = 0;
  int ok;

  if (!md || !ctx)
    die("libcrypto digest unavailable", name);
  ok = EVP_DigestInit_ex(ctx, md, NULL) && EVP_DigestUpdate(ctx, in, inlen);
  if (ok && xof)
    ok = EVP_DigestFinalXOF(ctx, out, outlen);
  else if (ok) {
    ok = EVP_DigestFinal_ex(ctx, out, &n);
    ok = ok && n == outlen;
  }
  EVP_MD_CTX_free(ctx);
  if (!ok)
    die("libcrypto digest failed", name);
}

/* ------------------------------------------------------------------ */
/* CAVP response files                                                 */

struct rsp {
  FILE *f;
  const char *path;
  char line[1 << 17];
};

/* Lines of NIST response files are short except Msg in LongMsg files. */
static char *g_bigline;
static size_t g_bigcap;

static int rsp_open(struct rsp *r, const char *dir, const char *name)
{
  static char path[4096];

  snprintf(path, sizeof path, "%s/%s", dir, name);
  r->path = path;
  r->f = fopen(path, "r");
  return r->f != NULL;
}

/*
 * Next "key = value" line, or a "[header]" line (key = "[", value = the
 * inside). Returns 0 at end of file. Comments and blank lines are skipped.
 */
static int rsp_next(struct rsp *r, char **key, char **val)
{
  for (;;) {
    size_t len = 0;
    int c;
    char *p, *eq;

    while ((c = fgetc(r->f)) != EOF && c != '\n') {
      if (len + 2 > g_bigcap) {
        g_bigcap = g_bigcap ? 2 * g_bigcap : 1 << 16;
        g_bigline = realloc(g_bigline, g_bigcap);
        if (!g_bigline)
          die("out of memory", NULL);
      }
      g_bigline[len++] = (char)c;
    }
    if (c == EOF && len == 0)
      return 0;
    if (!g_bigline) {
      g_bigcap = 1 << 16;
      g_bigline = xmalloc(g_bigcap);
    }
    g_bigline[len] = 0;
    while (len && (g_bigline[len - 1] == '\r' || g_bigline[len - 1] == ' '))
      g_bigline[--len] = 0;
    p = g_bigline;
    while (*p == ' ' || *p == '\t')
      p++;
    if (*p == 0 || *p == '#')
      continue;
    if (*p == '[') {
      char *end = strchr(p, ']');
      if (end)
        *end = 0;
      *key = "[";
      *val = p + 1;
      return 1;
    }
    eq = strchr(p, '=');
    if (!eq)
      die("malformed response line", r->path);
    *val = eq + 1;
    while (**val == ' ')
      (*val)++;
    while (eq > p && eq[-1] == ' ')
      eq--;
    *eq = 0;
    *key = p;
    return 1;
  }
}

static int hexval(int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static uint8_t *unhex(const char *s, size_t *n)
{
  size_t len = strlen(s), i;
  uint8_t *out;

  if (len % 2)
    die("odd-length hex string", s);
  out = xmalloc(len / 2);
  for (i = 0; i < len / 2; i++) {
    int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
    if (hi < 0 || lo < 0)
      die("bad hex digit", s);
    out[i] = (uint8_t)(hi << 4 | lo);
  }
  *n = len / 2;
  return out;
}

/*
 * A non-negative decimal field. The whole field must be the number:
 * trailing characters, an empty field and overflow are errors.
 */
static long number(const char *s)
{
  char *end;
  long n;

  errno = 0;
  n = strtol(s, &end, 10);
  if (end == s || *end || errno || n < 0)
    die("bad number", s);
  return n;
}

/* Header values look like "L = 256" or "Outputlen = 128". */
static long header_number(const char *hdr)
{
  const char *eq = strchr(hdr, '=');
  if (!eq)
    die("header without value", hdr);
  return number(eq + 1);
}

/* ShortMsg / LongMsg for fixed-length digests: Len (bits), Msg, MD. */
static unsigned long cavp_msg(const char *dir, const struct digest *d, const char *kind)
{
  struct rsp r;
  char name[64], what[128];
  char *k, *v;
  long len = -1;
  uint8_t *msg = NULL;
  size_t msglen = 0;
  unsigned long n = 0;

  snprintf(name, sizeof name, "%s%s.rsp", d->cavp, kind);
  if (!rsp_open(&r, dir, name))
    die("cannot open", r.path);
  while (rsp_next(&r, &k, &v)) {
    if (!strcmp(k, "Len"))
      len = number(v);
    else if (!strcmp(k, "Msg")) {
      free(msg);
      msg = unhex(v, &msglen);
    } else if (!strcmp(k, "MD")) {
      size_t mdlen;
      uint8_t *md = unhex(v, &mdlen);
      uint8_t got[64];

      if (len < 0 || len % 8 || !msg || mdlen != d->len)
        die("inconsistent record", r.path);
      if (len == 0)
        msglen = 0;
      if ((size_t)len / 8 != msglen)
        die("Len does not match Msg", r.path);
      d->fn(got, msg, msglen);
      snprintf(what, sizeof what, "%s Len=%ld", name, len);
      check(what, got, md, d->len);
      free(md);
      n++;
      len = -1;
    }
  }
  fclose(r.f);
  free(msg);
  if (n == 0)
    die("no test cases", r.path);
  return n;
}

/*
 * Monte Carlo tests.
 *
 * SHA-2 (SHAVS section 6.4): from Seed, each of 100 checkpoints runs
 * MD_i = H(MD_{i-3} || MD_{i-2} || MD_{i-1}) for i = 3 .. 1002 starting
 * from MD_0 = MD_1 = MD_2 = Seed, and the next Seed is MD_1002.
 *
 * SHA-3 (SHA3VS section 6.2.3): MD_i = H(MD_{i-1}) 1000 times per
 * checkpoint, continuing from the previous checkpoint.
 */
static unsigned long cavp_monte(const char *dir, const struct digest *d)
{
  struct rsp r;
  char name[64], what[128];
  char *k, *v;
  uint8_t md[3][64], m[3 * 64], seed[64];
  int have_seed = 0;
  unsigned long n = 0;
  long count = -1;

  snprintf(name, sizeof name, "%sMonte.rsp", d->cavp);
  if (!rsp_open(&r, dir, name))
    die("cannot open", r.path);
  while (rsp_next(&r, &k, &v)) {
    if (!strcmp(k, "Seed") || (!strcmp(k, "Msg") && d->sha3)) {
      size_t sl;
      uint8_t *s = unhex(v, &sl);
      if (sl != d->len)
        die("seed length", r.path);
      memcpy(seed, s, sl);
      free(s);
      have_seed = 1;
    } else if (!strcmp(k, "COUNT"))
      count = number(v);
    else if (!strcmp(k, "MD")) {
      size_t wl;
      uint8_t *want = unhex(v, &wl);
      int i;

      if (!have_seed || wl != d->len)
        die("inconsistent record", r.path);
      if (d->sha3) {
        for (i = 0; i < 1000; i++) {
          d->fn(md[0], seed, d->len);
          memcpy(seed, md[0], d->len);
        }
      } else {
        memcpy(md[0], seed, d->len);
        memcpy(md[1], seed, d->len);
        memcpy(md[2], seed, d->len);
        for (i = 3; i < 1003; i++) {
          memcpy(m, md[0], d->len);
          memcpy(m + d->len, md[1], d->len);
          memcpy(m + 2 * d->len, md[2], d->len);
          memcpy(md[0], md[1], d->len);
          memcpy(md[1], md[2], d->len);
          d->fn(md[2], m, 3 * d->len);
        }
        memcpy(seed, md[2], d->len);
      }
      snprintf(what, sizeof what, "%s COUNT=%ld", name, count);
      check(what, seed, want, d->len);
      free(want);
      n++;
    }
  }
  fclose(r.f);
  if (n != 100)
    die("expected 100 Monte Carlo checkpoints", r.path);
  return n;
}

/* SHAKE ShortMsg / LongMsg: header Outputlen (bits); Len, Msg, Output. */
static unsigned long cavp_shake_msg(const char *dir, const struct xof *x, const char *kind)
{
  struct rsp r;
  char name[64], what[128];
  char *k, *v;
  long len = -1, outbits = -1;
  uint8_t *msg = NULL;
  size_t msglen = 0;
  unsigned long n = 0;

  snprintf(name, sizeof name, "%s%s.rsp", x->cavp, kind);
  if (!rsp_open(&r, dir, name))
    die("cannot open", r.path);
  while (rsp_next(&r, &k, &v)) {
    if (!strcmp(k, "[") && !strncmp(v, "Outputlen", 9))
      outbits = header_number(v);
    else if (!strcmp(k, "Len"))
      len = number(v);
    else if (!strcmp(k, "Msg")) {
      free(msg);
      msg = unhex(v, &msglen);
    } else if (!strcmp(k, "Output")) {
      size_t wl;
      uint8_t *want = unhex(v, &wl);
      uint8_t *got;

      if (len < 0 || len % 8 || !msg || outbits <= 0 || (size_t)outbits / 8 != wl)
        die("inconsistent record", r.path);
      if (len == 0)
        msglen = 0;
      got = xmalloc(wl);
      x->fn(got, wl, msg, msglen);
      snprintf(what, sizeof what, "%s Len=%ld", name, len);
      check(what, got, want, wl);
      free(got);
      free(want);
      n++;
      len = -1;
    }
  }
  fclose(r.f);
  free(msg);
  if (n == 0)
    die("no test cases", r.path);
  return n;
}

/* SHAKE VariableOut: records COUNT, Outputlen (bits), Msg, Output. */
static unsigned long cavp_shake_varout(const char *dir, const struct xof *x)
{
  struct rsp r;
  char name[64], what[128];
  char *k, *v;
  long outbits = -1, count = -1;
  uint8_t *msg = NULL;
  size_t msglen = 0;
  unsigned long n = 0;

  snprintf(name, sizeof name, "%sVariableOut.rsp", x->cavp);
  if (!rsp_open(&r, dir, name))
    die("cannot open", r.path);
  while (rsp_next(&r, &k, &v)) {
    if (!strcmp(k, "COUNT"))
      count = number(v);
    else if (!strcmp(k, "Outputlen"))
      outbits = number(v);
    else if (!strcmp(k, "Msg")) {
      free(msg);
      msg = unhex(v, &msglen);
    } else if (!strcmp(k, "Output")) {
      size_t wl;
      uint8_t *want = unhex(v, &wl);
      uint8_t *got;

      if (!msg || outbits <= 0 || outbits % 8 || (size_t)outbits / 8 != wl)
        die("inconsistent record", r.path);
      got = xmalloc(wl);
      x->fn(got, wl, msg, msglen);
      snprintf(what, sizeof what, "%s COUNT=%ld", name, count);
      check(what, got, want, wl);
      free(got);
      free(want);
      n++;
    }
  }
  fclose(r.f);
  free(msg);
  if (n == 0)
    die("no test cases", r.path);
  return n;
}

/*
 * SHAKE Monte Carlo (SHA3VS section 6.2.3, byte form):
 *
 *     Output_0 = Msg, Outputlen = maxoutlen
 *     repeat 1000 times per checkpoint:
 *         M_i       = leftmost 16 bytes of Output_{i-1}, zero-padded
 *         Output_i  = SHAKE(M_i, Outputlen)
 *         Outputlen = minoutlen + (rightmost 16 bits of Output_i mod range)
 *
 * with lengths in bytes and range = maxoutlen - minoutlen + 1. Each
 * checkpoint records Output_1000 and its length.
 */
static unsigned long cavp_shake_monte(const char *dir, const struct xof *x)
{
  struct rsp r;
  char name[64], what[128];
  char *k, *v;
  long minb = -1, maxb = -1, count = -1;
  uint8_t prev[256], cur[256], m[16];
  size_t prevlen = 0, outlen = 0;
  int have_msg = 0;
  unsigned long n = 0;
  long recbits = -1;

  snprintf(name, sizeof name, "%sMonte.rsp", x->cavp);
  if (!rsp_open(&r, dir, name))
    die("cannot open", r.path);
  while (rsp_next(&r, &k, &v)) {
    if (!strcmp(k, "[") && strstr(v, "Minimum Output Length"))
      minb = header_number(v) / 8;
    else if (!strcmp(k, "[") && strstr(v, "Maximum Output Length"))
      maxb = header_number(v) / 8;
    else if (!strcmp(k, "Msg")) {
      size_t ml;
      uint8_t *s = unhex(v, &ml);
      if (ml != 16 || minb <= 0 || maxb < minb || maxb > (long)sizeof cur)
        die("unexpected Monte Carlo header", r.path);
      memcpy(prev, s, 16);
      prevlen = 16;
      outlen = (size_t)maxb;
      have_msg = 1;
      free(s);
    } else if (!strcmp(k, "COUNT"))
      count = number(v);
    else if (!strcmp(k, "Outputlen"))
      recbits = number(v);
    else if (!strcmp(k, "Output")) {
      size_t wl, last = 0;
      uint8_t *want = unhex(v, &wl);
      int i;

      if (!have_msg)
        die("Monte Carlo record before Msg", r.path);
      for (i = 0; i < 1000; i++) {
        size_t range = (size_t)(maxb - minb + 1);
        unsigned bits16;

        memset(m, 0, 16);
        memcpy(m, prev, prevlen < 16 ? prevlen : 16);
        x->fn(cur, outlen, m, 16);
        last = outlen;
        bits16 = (unsigned)cur[outlen - 2] << 8 | cur[outlen - 1];
        memcpy(prev, cur, outlen);
        prevlen = outlen;
        outlen = (size_t)minb + bits16 % range;
      }
      snprintf(what, sizeof what, "%s COUNT=%ld", name, count);
      if (recbits < 0 || (size_t)recbits != 8 * last || wl != last) {
        g_fail++;
        fprintf(stderr, "FAIL %s: output length %zu, record %ld bits\n", what, last, recbits);
      } else
        check(what, prev, want, wl);
      free(want);
      n++;
    }
  }
  fclose(r.f);
  if (n != 100)
    die("expected 100 Monte Carlo checkpoints", r.path);
  return n;
}

/* HMAC.rsp: sections [L=32] (SHA-256) and [L=64] (SHA-512) are run. */
static unsigned long cavp_hmac(const char *dir, unsigned long *skipped)
{
  struct rsp r;
  char what[128];
  char *k, *v;
  long L = -1, tlen = -1, klen = -1, count = -1;
  uint8_t *key = NULL, *msg = NULL;
  size_t keylen = 0, msglen = 0;
  unsigned long n = 0;

  *skipped = 0;
  if (!rsp_open(&r, dir, "HMAC.rsp"))
    die("cannot open", r.path);
  while (rsp_next(&r, &k, &v)) {
    if (!strcmp(k, "["))
      L = header_number(v);
    else if (!strcmp(k, "Count"))
      count = number(v);
    else if (!strcmp(k, "Klen"))
      klen = number(v);
    else if (!strcmp(k, "Tlen"))
      tlen = number(v);
    else if (!strcmp(k, "Key")) {
      free(key);
      key = unhex(v, &keylen);
    } else if (!strcmp(k, "Msg")) {
      free(msg);
      msg = unhex(v, &msglen);
    } else if (!strcmp(k, "Mac")) {
      size_t wl;
      uint8_t *want = unhex(v, &wl);
      uint8_t tag[64];

      if (!key || !msg || (size_t)klen != keylen || (size_t)tlen != wl)
        die("inconsistent record", r.path);
      if (L == 32 || L == 64) {
        if (L == 32)
          HT(hmac_sha256)(tag, key, keylen, msg, msglen);
        else
          HT(hmac_sha512)(tag, key, keylen, msg, msglen);
        snprintf(what, sizeof what, "HMAC.rsp L=%ld Count=%ld", L, count);
        check(what, tag, want, wl);
        n++;
      } else
        (*skipped)++;
      free(want);
    }
  }
  fclose(r.f);
  free(key);
  free(msg);
  if (n == 0)
    die("no HMAC-SHA-256/512 cases", r.path);
  return n;
}

/*
 * Keccak-f[1600] applied to the all-zero state, then to its own output:
 * the two examples of KeccakF-1600-IntermediateValues.txt in XKCP
 * (tests/TestVectors). Lane (x, y) is word x + 5y.
 */
static const uint64_t KECCAKF_ZERO[2][25] = {
  { 0xf1258f7940e1dde7ull, 0x84d5ccf933c0478aull, 0xd598261ea65aa9eeull, 0xbd1547306f80494dull,
    0x8b284e056253d057ull, 0xff97a42d7f8e6fd4ull, 0x90fee5a0a44647c4ull, 0x8c5bda0cd6192e76ull,
    0xad30a6f71b19059cull, 0x30935ab7d08ffc64ull, 0xeb5aa93f2317d635ull, 0xa9a6e6260d712103ull,
    0x81a57c16dbcf555full, 0x43b831cd0347c826ull, 0x01f22f1a11a5569full, 0x05e5635a21d9ae61ull,
    0x64befef28cc970f2ull, 0x613670957bc46611ull, 0xb87c5a554fd00ecbull, 0x8c3ee88a1ccf32c8ull,
    0x940c7922ae3a2614ull, 0x1841f924a2c509e4ull, 0x16f53526e70465c2ull, 0x75f644e97f30a13bull,
    0xeaf1ff7b5ceca249ull },
  { 0x2d5c954df96ecb3cull, 0x6a332cd07057b56dull, 0x093d8d1270d76b6cull, 0x8a20d9b25569d094ull,
    0x4f9c4f99e5e7f156ull, 0xf957b9a2da65fb38ull, 0x85773dae1275af0dull, 0xfaf4f247c3d810f7ull,
    0x1f1b9ee6f79a8759ull, 0xe4fecc0fee98b425ull, 0x68ce61b6b9ce68a1ull, 0xdeea66c4ba8f974full,
    0x33c43d836eafb1f5ull, 0xe00654042719dbd9ull, 0x7cf8a9f009831265ull, 0xfd5449a6bf174743ull,
    0x97ddad33d8994b40ull, 0x48ead5fc5d0be774ull, 0xe3b8c8ee55b7b03cull, 0x91a0226e649e42e9ull,
    0x900e3129e7badd7bull, 0x202a9ec5faa3cce8ull, 0x5b3402464e1c3db6ull, 0x609f4e62a44c1059ull,
    0x20d06cd26a8fbf5cull },
};

static unsigned long kat_keccakf(void)
{
  uint64_t st[25];
  char what[64];
  int i;

  memset(st, 0, sizeof st);
  for (i = 0; i < 2; i++) {
    HT(keccakf1600)(st);
    snprintf(what, sizeof what, "Keccak-f[1600] zero state, application %d", i + 1);
    check(what, (const uint8_t *)st, (const uint8_t *)KECCAKF_ZERO[i], sizeof st);
  }
  return 2;
}

static int run_cavp(const char *dir)
{
  size_t i;
  unsigned long n, skipped;

  printf("kat  Keccak-f[1600] zero state %lu\n", kat_keccakf());
  for (i = 0; i < sizeof DIGESTS / sizeof DIGESTS[0]; i++) {
    unsigned long s = cavp_msg(dir, &DIGESTS[i], "ShortMsg");
    unsigned long l = cavp_msg(dir, &DIGESTS[i], "LongMsg");
    unsigned long m = cavp_monte(dir, &DIGESTS[i]);
    printf("cavp %-11s ShortMsg %4lu  LongMsg %4lu  Monte %3lu\n", DIGESTS[i].cavp, s, l, m);
  }
  for (i = 0; i < sizeof XOFS / sizeof XOFS[0]; i++) {
    unsigned long s = cavp_shake_msg(dir, &XOFS[i], "ShortMsg");
    unsigned long l = cavp_shake_msg(dir, &XOFS[i], "LongMsg");
    unsigned long vo = cavp_shake_varout(dir, &XOFS[i]);
    unsigned long m = cavp_shake_monte(dir, &XOFS[i]);
    printf("cavp %-11s ShortMsg %4lu  LongMsg %4lu  VariableOut %4lu  Monte %3lu\n", XOFS[i].cavp, s,
           l, vo, m);
  }
  n = cavp_hmac(dir, &skipped);
  printf("cavp HMAC        cases %lu (L=32, L=64); %lu cases of other hashes not applicable\n", n,
         skipped);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Differential tests                                                  */

/* splitmix64: a reproducible stream from the printed seed. */
static uint64_t g_rng;

static uint64_t rnd(void)
{
  uint64_t z = (g_rng += 0x9e3779b97f4a7c15ull);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

static size_t rnd_below(size_t n)
{
  return n ? (size_t)(rnd() % n) : 0;
}

static void rnd_bytes(uint8_t *p, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++)
    p[i] = (uint8_t)rnd();
}

/*
 * Message lengths concentrate on block boundaries (all rates and SHA-2
 * block sizes, +-2) and otherwise spread up to a few blocks; one case in
 * 64 is long.
 */
static size_t rnd_len(void)
{
  static const size_t edges[] = { 0, 1, 55, 56, 63, 64, 65, 71, 72, 103, 104, 111, 112, 119, 120,
                                  127, 128, 129, 135, 136, 137, 143, 144, 167, 168, 169, 239,
                                  240, 255, 256, 272, 336 };
  switch (rnd_below(4)) {
  case 0:
    return edges[rnd_below(sizeof edges / sizeof edges[0])] + rnd_below(3);
  case 1:
    return rnd_below(64) == 0 ? 2000 + rnd_below(6000) : rnd_below(600);
  default:
    return rnd_below(400);
  }
}

#define MAXMSG 8192

struct keccak_mode {
  const char *ossl;
  uint64_t rate, ds;
  size_t dlen;  /* 0 for SHAKE */
};

static const struct keccak_mode KMODES[] = {
  { "SHA3-224", 144, 0x06, 28 }, { "SHA3-256", 136, 0x06, 32 },
  { "SHA3-384", 104, 0x06, 48 }, { "SHA3-512", 72, 0x06, 64 },
  { "SHAKE128", 168, 0x1f, 0 },  { "SHAKE256", 136, 0x1f, 0 },
};

/* Absorb msg in random pieces through the memory form; returns pos. */
static uint64_t keccak_absorb_split(uint64_t st[25], uint64_t pos, uint64_t rate, const uint8_t *msg,
                                    size_t len)
{
  size_t off = 0;
  while (off < len) {
    size_t piece = rnd_below(4) == 0 ? len - off : rnd_below(len - off + 1);
    pos = HT(keccak_absorb)(st, pos, rate, msg + off, piece);
    if (pos >= rate)
      die("absorb returned pos >= rate", NULL);
    off += piece;
  }
  return pos;
}

static uint64_t keccak_squeeze_split(uint64_t st[25], uint64_t pos, uint64_t rate, uint8_t *out,
                                     size_t len)
{
  size_t off = 0;
  while (off < len) {
    size_t piece = rnd_below(4) == 0 ? len - off : rnd_below(len - off + 1);
    pos = HT(keccak_squeeze)(st, pos, rate, out + off, piece);
    off += piece;
  }
  return pos;
}

static void diff_keccak(unsigned long iter, uint8_t *msg, size_t len)
{
  const struct keccak_mode *km = &KMODES[rnd_below(6)];
  size_t outlen = km->dlen ? km->dlen : rnd_below(700);
  uint8_t got[700], want[700], oneshot[64];
  uint64_t st[25];
  uint64_t pos;
  char what[160];

  ossl_digest(km->ossl, msg, len, want, outlen, km->dlen == 0);

  memset(st, 0, sizeof st);
  pos = keccak_absorb_split(st, 0, km->rate, msg, len);
  HT(keccak_finalize)(st, pos, km->rate, km->ds);
  keccak_squeeze_split(st, 0, km->rate, got, outlen);
  snprintf(what, sizeof what, "diff iter %lu %s split len=%zu out=%zu", iter, km->ossl, len, outlen);
  if (!check(what, got, want, outlen))
    hexdump("msg", msg, len);

  /* One-shot exports. */
  if (km->dlen) {
    if (km->dlen == 28)
      HT(sha3_224)(oneshot, msg, len);
    else if (km->dlen == 32)
      HT(sha3_256)(oneshot, msg, len);
    else if (km->dlen == 48)
      HT(sha3_384)(oneshot, msg, len);
    else
      HT(sha3_512)(oneshot, msg, len);
    snprintf(what, sizeof what, "diff iter %lu %s one-shot len=%zu", iter, km->ossl, len);
    check(what, oneshot, want, km->dlen);
  } else {
    if (km->rate == 168)
      HT(shake128)(got, outlen, msg, len);
    else
      HT(shake256)(got, outlen, msg, len);
    snprintf(what, sizeof what, "diff iter %lu %s one-shot len=%zu out=%zu", iter, km->ossl, len,
             outlen);
    check(what, got, want, outlen);
  }
}

struct sha2_mode {
  const char *ossl;
  int wide;           /* 0: SHA-256 core, 1: SHA-512 core */
  int variant;        /* initial value */
  size_t dlen;
  digest_fn oneshot;
};

static const struct sha2_mode SMODES[] = {
  { "SHA224", 0, 1, 28, HT(sha224) },         { "SHA256", 0, 0, 32, HT(sha256) },
  { "SHA384", 1, 1, 48, HT(sha384) },         { "SHA512", 1, 0, 64, HT(sha512) },
  { "SHA512-224", 1, 2, 28, HT(sha512_224) }, { "SHA512-256", 1, 3, 32, HT(sha512_256) },
};

static void diff_sha2(unsigned long iter, uint8_t *msg, size_t len)
{
  const struct sha2_mode *sm = &SMODES[rnd_below(6)];
  uint8_t want[64], got[64];
  char what[160];
  size_t off = 0;
  uint64_t total = 0;

  ossl_digest(sm->ossl, msg, len, want, sm->dlen, 0);

  sm->oneshot(got, msg, len);
  snprintf(what, sizeof what, "diff iter %lu %s one-shot len=%zu", iter, sm->ossl, len);
  if (!check(what, got, want, sm->dlen))
    hexdump("msg", msg, len);

  if (!sm->wide) {
    uint32_t h[8];
    uint8_t buf[64];

    (sm->variant ? HT(sha224_init) : HT(sha256_init))(h);
    while (off < len) {
      size_t piece = rnd_below(3) == 0 ? len - off : rnd_below(len - off + 1);
      total = HT(sha256_absorb)(h, buf, total, msg + off, piece);
      off += piece;
    }
    HT(sha256_finalize)(got, h, buf, total);
  } else {
    uint64_t h[8];
    uint8_t buf[128];

    switch (sm->variant) {
    case 0: HT(sha512_init)(h); break;
    case 1: HT(sha384_init)(h); break;
    case 2: HT(sha512_224_init)(h); break;
    default: HT(sha512_256_init)(h); break;
    }
    while (off < len) {
      size_t piece = rnd_below(3) == 0 ? len - off : rnd_below(len - off + 1);
      total = HT(sha512_absorb)(h, buf, total, msg + off, piece);
      off += piece;
    }
    HT(sha512_finalize)(got, h, buf, total);
  }
  if (total != len)
    die("absorb total mismatch", sm->ossl);
  snprintf(what, sizeof what, "diff iter %lu %s split len=%zu", iter, sm->ossl, len);
  check(what, got, want, sm->dlen);
}

/*
 * A total no test message reaches: finalize alone, from a random chaining
 * value and pending block, with total up to 2^61 - 1 bytes (the contract's
 * limit), so the length field carries bits above 2^32. The expected value
 * lays out the padding and length here (FIPS 180-4 section 5.1) and runs
 * the compression export, which the CAVP and one-shot tests cover.
 */
static uint64_t rnd_total(void)
{
  static const uint64_t edges[] = { (1ull << 29) - 1, 1ull << 29, (1ull << 32) - 1, 1ull << 32,
                                    (1ull << 32) + 5, (1ull << 61) - 64, (1ull << 61) - 1 };
  if (rnd_below(2))
    return edges[rnd_below(sizeof edges / sizeof edges[0])];
  return rnd() & ((1ull << 61) - 1);
}

/* Pad pending bytes into one or two blocks of size bs whose last lf bytes hold the length. */
static size_t pad_final(uint8_t *blocks, const uint8_t *pending, uint64_t total, size_t bs, size_t lf)
{
  size_t fill = (size_t)(total % bs), n = fill + 1 + lf <= bs ? bs : 2 * bs, i;
  uint64_t bits_hi = total >> 61, bits_lo = total << 3;

  memset(blocks, 0, n);
  memcpy(blocks, pending, fill);
  blocks[fill] = 0x80;
  for (i = 0; i < 8; i++) {
    blocks[n - 1 - i] = (uint8_t)(bits_lo >> (8 * i));
    if (lf == 16)
      blocks[n - 9 - i] = (uint8_t)(bits_hi >> (8 * i));
  }
  return n;
}

static void diff_length(unsigned long iter)
{
  uint8_t blocks[256], got[64], want[64];
  char what[96];
  size_t n, i;

  {
    uint64_t total = rnd_total();
    uint32_t h[8], ref[8];
    uint8_t buf[64];

    for (i = 0; i < 8; i++)
      h[i] = ref[i] = (uint32_t)rnd();
    rnd_bytes(buf, sizeof buf);
    n = pad_final(blocks, buf, total, 64, 8);
    for (i = 0; i < n; i += 64)
      HT(sha256_compress)(ref, blocks + i);
    for (i = 0; i < 32; i++)
      want[i] = (uint8_t)(ref[i / 4] >> (8 * (3 - i % 4)));
    HT(sha256_finalize)(got, h, buf, total);
    snprintf(what, sizeof what, "diff iter %lu sha256 finalize total=%llu", iter,
             (unsigned long long)total);
    check(what, got, want, 32);
  }
  {
    uint64_t total = rnd_total();
    uint64_t h[8], ref[8];
    uint8_t buf[128];

    for (i = 0; i < 8; i++)
      h[i] = ref[i] = rnd();
    rnd_bytes(buf, sizeof buf);
    n = pad_final(blocks, buf, total, 128, 16);
    for (i = 0; i < n; i += 128)
      HT(sha512_compress)(ref, blocks + i);
    for (i = 0; i < 64; i++)
      want[i] = (uint8_t)(ref[i / 8] >> (8 * (7 - i % 8)));
    HT(sha512_finalize)(got, h, buf, total);
    snprintf(what, sizeof what, "diff iter %lu sha512 finalize total=%llu", iter,
             (unsigned long long)total);
    check(what, got, want, 64);
  }
}

/*
 * The array and multi-block compression entry points agree: n blocks
 * through _sha*_compress_blocks equal n single-block compressions,
 * n = 0 .. 4.
 */
static void diff_compress(unsigned long iter)
{
  uint8_t blocks[512];
  uint32_t a32[8], b32[8];
  uint64_t a64[8], b64[8];
  char what[96];
  size_t i, n = rnd_below(5);

  rnd_bytes(blocks, sizeof blocks);
  for (i = 0; i < 8; i++) {
    a32[i] = b32[i] = (uint32_t)rnd();
    a64[i] = b64[i] = rnd();
  }
  for (i = 0; i < n; i++)
    HT(sha256_compress)(a32, blocks + 64 * i);
  HT(sha256_compress_blocks)(b32, blocks, n);
  snprintf(what, sizeof what, "diff iter %lu sha256 compress array/blocks n=%zu", iter, n);
  check(what, (uint8_t *)a32, (uint8_t *)b32, sizeof a32);
  for (i = 0; i < n; i++)
    HT(sha512_compress)(a64, blocks + 128 * i);
  HT(sha512_compress_blocks)(b64, blocks, n);
  snprintf(what, sizeof what, "diff iter %lu sha512 compress array/blocks n=%zu", iter, n);
  check(what, (uint8_t *)a64, (uint8_t *)b64, sizeof a64);
}

static void diff_hmac(unsigned long iter, uint8_t *msg, size_t len)
{
  uint8_t key[300], want[64], got[64];
  size_t keylen;
  unsigned int n = 0;
  char what[160];
  int wide = (int)rnd_below(2);

  /*
   * Key lengths cover below, at and above one block (above it, FIPS 198-1
   * hashes the key).
   */
  switch (rnd_below(3)) {
  case 0: keylen = rnd_below(33); break;
  case 1: keylen = (wide ? 128 : 64) + rnd_below(3) - 1; break;
  default: keylen = rnd_below(sizeof key + 1); break;
  }
  rnd_bytes(key, keylen);
  if (!HMAC(EVP_get_digestbyname(wide ? "SHA512" : "SHA256"), key, (int)keylen, msg, len, want, &n))
    die("libcrypto HMAC failed", NULL);
  if (wide)
    HT(hmac_sha512)(got, key, keylen, msg, len);
  else
    HT(hmac_sha256)(got, key, keylen, msg, len);
  snprintf(what, sizeof what, "diff iter %lu HMAC-SHA-%s keylen=%zu len=%zu", iter,
           wide ? "512" : "256", keylen, len);
  if (!check(what, got, want, n)) {
    hexdump("key", key, keylen);
    hexdump("msg", msg, len);
  }
}

/* MGF1 (RFC 8017 B.2.1) composed from libcrypto SHA-2. */
static void mgf1_oracle(const char *md, size_t hlen, const uint8_t *seed, size_t seedlen,
                        uint8_t *out, size_t outlen)
{
  uint8_t in[256], d[64];
  uint32_t c;

  memcpy(in, seed, seedlen);
  for (c = 0; (size_t)c * hlen < outlen; c++) {
    size_t take = outlen - c * hlen < hlen ? outlen - c * hlen : hlen;
    in[seedlen] = (uint8_t)(c >> 24);
    in[seedlen + 1] = (uint8_t)(c >> 16);
    in[seedlen + 2] = (uint8_t)(c >> 8);
    in[seedlen + 3] = (uint8_t)c;
    ossl_digest(md, in, seedlen + 4, d, hlen, 0);
    memcpy(out + c * hlen, d, take);
  }
}

struct mgf1_case {
  void (*fn)(uint8_t *, const uint8_t *);
  const char *md;
  size_t hlen, seedlen, outlen;
};

static const struct mgf1_case MGF1[] = {
  { HT(mgf1_sha256_64_30), "SHA256", 32, 64, 30 },   { HT(mgf1_sha256_64_34), "SHA256", 32, 64, 34 },
  { HT(mgf1_sha512_112_39), "SHA512", 64, 112, 39 }, { HT(mgf1_sha512_112_42), "SHA512", 64, 112, 42 },
  { HT(mgf1_sha512_128_47), "SHA512", 64, 128, 47 }, { HT(mgf1_sha512_128_49), "SHA512", 64, 128, 49 },
};

static void diff_mgf1(unsigned long iter)
{
  const struct mgf1_case *mc = &MGF1[rnd_below(6)];
  uint8_t seed[128], got[64], want[64];
  char what[96];

  rnd_bytes(seed, mc->seedlen);
  mgf1_oracle(mc->md, mc->hlen, seed, mc->seedlen, want, mc->outlen);
  mc->fn(got, seed);
  snprintf(what, sizeof what, "diff iter %lu MGF1-%s seed=%zu out=%zu", iter, mc->md, mc->seedlen,
           mc->outlen);
  check(what, got, want, mc->outlen);
}

/* Array instances, checked after a random prefix through the memory forms. */
struct array_case {
  size_t len;
  uint64_t (*kabs)(uint64_t *, uint64_t, uint64_t, const uint8_t *);
  uint64_t (*ksqz)(uint8_t *, uint64_t *, uint64_t, uint64_t);
  uint64_t (*s256)(uint32_t *, uint8_t *, uint64_t, const uint8_t *);
  uint64_t (*s512)(uint64_t *, uint8_t *, uint64_t, const uint8_t *);
};

#define ARRAY_CASE(L)                                                                          \
  { L, HT(keccak_absorb_array_##L), HT(keccak_squeeze_array_##L), HT(sha256_absorb_array_##L), \
    HT(sha512_absorb_array_##L) }

static const struct array_case ARRAYS[] = {
  ARRAY_CASE(1),  ARRAY_CASE(7),  ARRAY_CASE(16),  ARRAY_CASE(22),  ARRAY_CASE(32),
  ARRAY_CASE(64), ARRAY_CASE(65), ARRAY_CASE(129), ARRAY_CASE(200),
};

static void diff_arrays(unsigned long iter, uint8_t *msg)
{
  const struct array_case *ac = &ARRAYS[rnd_below(sizeof ARRAYS / sizeof ARRAYS[0])];
  const struct keccak_mode *km = &KMODES[4 + rnd_below(2)];
  size_t pre = rnd_below(400), skip = rnd_below(400), more = 1 + rnd_below(200);
  uint8_t want[1024], got[512];
  uint64_t st[25], pos;
  char what[160];

  /*
   * Keccak absorb: prefix (memory form) || array, then squeeze from skip;
   * the memory form continues from the position the array instance
   * returns.
   */
  ossl_digest(km->ossl, msg, pre + ac->len, want, skip + ac->len + more, 1);
  memset(st, 0, sizeof st);
  pos = HT(keccak_absorb)(st, 0, km->rate, msg, pre);
  pos = ac->kabs(st, pos, km->rate, msg + pre);
  HT(keccak_finalize)(st, pos, km->rate, km->ds);
  pos = HT(keccak_squeeze)(st, 0, km->rate, got, skip);
  pos = ac->ksqz(got, st, pos, km->rate);
  HT(keccak_squeeze)(st, pos, km->rate, got + ac->len, more);
  snprintf(what, sizeof what, "diff iter %lu %s array L=%zu prefix=%zu skip=%zu more=%zu", iter,
           km->ossl, ac->len, pre, skip, more);
  check(what, got, want + skip, ac->len + more);

  /* SHA-256 and SHA-512: prefix (memory form) || array. */
  {
    uint32_t h[8];
    uint8_t buf[64];
    uint64_t total;

    HT(sha256_init)(h);
    total = HT(sha256_absorb)(h, buf, 0, msg, pre);
    total = ac->s256(h, buf, total, msg + pre);
    HT(sha256_finalize)(got, h, buf, total);
    ossl_digest("SHA256", msg, pre + ac->len, want, 32, 0);
    snprintf(what, sizeof what, "diff iter %lu SHA256 array L=%zu prefix=%zu", iter, ac->len, pre);
    check(what, got, want, 32);
  }
  {
    uint64_t h[8];
    uint8_t buf[128];
    uint64_t total;

    HT(sha512_init)(h);
    total = HT(sha512_absorb)(h, buf, 0, msg, pre);
    total = ac->s512(h, buf, total, msg + pre);
    HT(sha512_finalize)(got, h, buf, total);
    ossl_digest("SHA512", msg, pre + ac->len, want, 64, 0);
    snprintf(what, sizeof what, "diff iter %lu SHA512 array L=%zu prefix=%zu", iter, ac->len, pre);
    check(what, got, want, 64);
  }
}

/*
 * 4-way Keccak. The permutation is compared with four single-way
 * permutations, and the init must clear the permuted state. The 4-way
 * sponge is compared with libcrypto per instance, over two absorbed arrays
 * and two squeezed arrays of random tested lengths, so that pos crosses
 * lane and block boundaries, for all six SHA-3 and SHAKE domains.
 */
struct x4_case {
  size_t len;
  uint64_t (*abs)(uint64_t *, uint64_t, uint64_t, const uint8_t *);
  uint64_t (*sqz)(uint8_t *, uint64_t *, uint64_t, uint64_t);
};

#define X4_CASE(L) { L, HT(keccak_x4_absorb_array_##L), HT(keccak_x4_squeeze_array_##L) }

static const struct x4_case X4[] = {
  X4_CASE(1),  X4_CASE(7),  X4_CASE(16),  X4_CASE(22),  X4_CASE(32),
  X4_CASE(64), X4_CASE(65), X4_CASE(129), X4_CASE(200),
};

static const uint64_t ZERO_X4[100];

static void diff_keccak_x4(unsigned long iter)
{
  const struct keccak_mode *km = &KMODES[rnd_below(6)];
  const struct x4_case *a = &X4[rnd_below(9)], *b = &X4[rnd_below(9)];
  const struct x4_case *c = &X4[rnd_below(9)], *d = &X4[rnd_below(9)];
  uint64_t st4[100], one[4][25];
  uint8_t ina[4 * 200], inb[4 * 200], outc[4 * 200], outd[4 * 200];
  uint8_t msg[400], want[400];
  uint64_t pos;
  char what[160];
  int k, j;

  /* Permutation */
  for (j = 0; j < 25; j++)
    for (k = 0; k < 4; k++)
      st4[4 * j + k] = one[k][j] = rnd();
  HT(keccakf1600_x4)(st4);
  for (k = 0; k < 4; k++) {
    uint64_t got[25];
    HT(keccakf1600)(one[k]);
    for (j = 0; j < 25; j++)
      got[j] = st4[4 * j + k];
    snprintf(what, sizeof what, "diff iter %lu keccakf1600_x4 instance %d", iter, k);
    check(what, (uint8_t *)got, (uint8_t *)one[k], sizeof got);
  }

  /* Sponge: absorb a then b, finalize, squeeze c then d */
  rnd_bytes(ina, sizeof ina);
  rnd_bytes(inb, sizeof inb);
  /* st4 still holds the permuted random state */
  HT(keccak_x4_init)(st4);
  snprintf(what, sizeof what, "diff iter %lu keccak_x4_init", iter);
  check(what, (uint8_t *)st4, (const uint8_t *)ZERO_X4, sizeof st4);
  pos = a->abs(st4, 0, km->rate, ina);
  pos = b->abs(st4, pos, km->rate, inb);
  HT(keccak_x4_finalize)(st4, pos, km->rate, km->ds);
  pos = c->sqz(outc, st4, 0, km->rate);
  d->sqz(outd, st4, pos, km->rate);
  /*
   * SHAKE: the whole squeezed stream. SHA-3: the stream's first d bytes are
   * the digest, so the comparison covers min(d, squeezed) bytes.
   */
  for (k = 0; k < 4; k++) {
    uint8_t got[400];
    size_t n = c->len + d->len;

    memcpy(msg, ina + k * a->len, a->len);
    memcpy(msg + a->len, inb + k * b->len, b->len);
    memcpy(got, outc + k * c->len, c->len);
    memcpy(got + c->len, outd + k * d->len, d->len);
    if (km->dlen) {
      ossl_digest(km->ossl, msg, a->len + b->len, want, km->dlen, 0);
      n = n < km->dlen ? n : km->dlen;
    } else
      ossl_digest(km->ossl, msg, a->len + b->len, want, n, 1);
    snprintf(what, sizeof what, "diff iter %lu %s keccak_x4 instance %d absorb %zu+%zu squeeze %zu+%zu", iter,
             km->ossl, k, a->len, b->len, c->len, d->len);
    check(what, got, want, n);
  }
}

/*
 * Multi-way SHA-2. Each compression is compared with the single-way
 * compression of every instance; the absorb and finalize layer with
 * libcrypto per instance, over two absorbed arrays of random tested lengths.
 */
struct shax_case {
  size_t len;
  uint64_t (*s256)(uint32_t *, uint8_t *, uint64_t, const uint8_t *);
  uint64_t (*s512)(uint64_t *, uint8_t *, uint64_t, const uint8_t *);
};

#define SHAX_CASE(L) { L, HT(sha256_x8_absorb_array_##L), HT(sha512_x4_absorb_array_##L) }

static const struct shax_case SHAX[] = {
  SHAX_CASE(1),  SHAX_CASE(7),  SHAX_CASE(16),  SHAX_CASE(22),  SHAX_CASE(32),
  SHAX_CASE(64), SHAX_CASE(65), SHAX_CASE(129), SHAX_CASE(200),
};

static void diff_sha2_multi(unsigned long iter)
{
  const struct shax_case *a = &SHAX[rnd_below(9)], *b = &SHAX[rnd_below(9)];
  uint8_t blocks[512], ina[8 * 200], inb[8 * 200], buf[512], out[256], msg[400], want[64];
  char what[160];
  int k, j;

  rnd_bytes(blocks, sizeof blocks);
  rnd_bytes(ina, sizeof ina);
  rnd_bytes(inb, sizeof inb);
  rnd_bytes(buf, sizeof buf);

  {
    uint32_t h8[64], one[8];
    int v = (int)rnd_below(2);
    const char *md = v ? "SHA224" : "SHA256";
    size_t dl = v ? 28 : 32;
    uint64_t total;

    for (j = 0; j < 64; j++)
      h8[j] = (uint32_t)rnd();
    {
      uint32_t ref[64];
      memcpy(ref, h8, sizeof ref);
      HT(sha256_x8_compress)(h8, blocks);
      for (k = 0; k < 8; k++) {
        for (j = 0; j < 8; j++)
          one[j] = ref[8 * j + k];
        HT(sha256_compress)(one, blocks + 64 * k);
        for (j = 0; j < 8; j++)
          ref[8 * j + k] = one[j];
      }
      snprintf(what, sizeof what, "diff iter %lu sha256_x8_compress", iter);
      check(what, (uint8_t *)h8, (uint8_t *)ref, sizeof ref);
    }

    (v ? HT(sha224_x8_init) : HT(sha256_x8_init))(h8);
    total = a->s256(h8, buf, 0, ina);
    total = b->s256(h8, buf, total, inb);
    HT(sha256_x8_finalize)(out, h8, buf, total);
    for (k = 0; k < 8; k++) {
      memcpy(msg, ina + k * a->len, a->len);
      memcpy(msg + a->len, inb + k * b->len, b->len);
      ossl_digest(md, msg, a->len + b->len, want, dl, 0);
      snprintf(what, sizeof what, "diff iter %lu %s sha256_x8 instance %d absorb %zu+%zu", iter, md, k, a->len,
               b->len);
      check(what, out + 32 * k, want, dl);
    }
  }

  {
    static const char *const mds[] = { "SHA512", "SHA384", "SHA512-224", "SHA512-256" };
    static const size_t dls[] = { 64, 48, 28, 32 };
    uint64_t h4[32], one[8], ref[32];
    int v = (int)rnd_below(4);
    uint64_t total;

    for (j = 0; j < 32; j++)
      h4[j] = rnd();
    memcpy(ref, h4, sizeof ref);
    HT(sha512_x4_compress)(h4, blocks);
    for (k = 0; k < 4; k++) {
      for (j = 0; j < 8; j++)
        one[j] = ref[4 * j + k];
      HT(sha512_compress)(one, blocks + 128 * k);
      for (j = 0; j < 8; j++)
        ref[4 * j + k] = one[j];
    }
    snprintf(what, sizeof what, "diff iter %lu sha512_x4_compress", iter);
    check(what, (uint8_t *)h4, (uint8_t *)ref, sizeof ref);

    switch (v) {
    case 0: HT(sha512_x4_init)(h4); break;
    case 1: HT(sha384_x4_init)(h4); break;
    case 2: HT(sha512_224_x4_init)(h4); break;
    default: HT(sha512_256_x4_init)(h4); break;
    }
    total = a->s512(h4, buf, 0, ina);
    total = b->s512(h4, buf, total, inb);
    HT(sha512_x4_finalize)(out, h4, buf, total);
    for (k = 0; k < 4; k++) {
      memcpy(msg, ina + k * a->len, a->len);
      memcpy(msg + a->len, inb + k * b->len, b->len);
      ossl_digest(mds[v], msg, a->len + b->len, want, dls[v], 0);
      snprintf(what, sizeof what, "diff iter %lu %s sha512_x4 instance %d absorb %zu+%zu", iter, mds[v], k,
               a->len, b->len);
      check(what, out + 64 * k, want, dls[v]);
    }
  }
}

/*
 * The multi-way finalize lays out padding and length itself, so it gets
 * the test diff_length gives the single-way one: a random total up to
 * 2^61 - 1 bytes, shared by the instances, a random chaining value and
 * pending block per instance, and each instance compared with padding laid
 * out here and the single-way compression export.
 */
static void diff_length_multi(unsigned long iter)
{
  uint8_t blocks[256], buf[512], out[256], ref[256];
  char what[128];
  size_t n, i;
  int k, j;

  {
    uint64_t total = rnd_total();
    uint32_t h8[64], one[8];

    for (j = 0; j < 64; j++)
      h8[j] = (uint32_t)rnd();
    rnd_bytes(buf, sizeof buf);
    for (k = 0; k < 8; k++) {
      for (j = 0; j < 8; j++)
        one[j] = h8[8 * j + k];
      n = pad_final(blocks, buf + 64 * k, total, 64, 8);
      for (i = 0; i < n; i += 64)
        HT(sha256_compress)(one, blocks + i);
      for (i = 0; i < 32; i++)
        ref[32 * k + i] = (uint8_t)(one[i / 4] >> (8 * (3 - i % 4)));
    }
    HT(sha256_x8_finalize)(out, h8, buf, total);
    for (k = 0; k < 8; k++) {
      snprintf(what, sizeof what, "diff iter %lu sha256_x8 finalize instance %d total=%llu", iter, k,
               (unsigned long long)total);
      check(what, out + 32 * k, ref + 32 * k, 32);
    }
  }
  {
    uint64_t total = rnd_total();
    uint64_t h4[32], one[8];

    for (j = 0; j < 32; j++)
      h4[j] = rnd();
    rnd_bytes(buf, sizeof buf);
    for (k = 0; k < 4; k++) {
      for (j = 0; j < 8; j++)
        one[j] = h4[4 * j + k];
      n = pad_final(blocks, buf + 128 * k, total, 128, 16);
      for (i = 0; i < n; i += 128)
        HT(sha512_compress)(one, blocks + i);
      for (i = 0; i < 64; i++)
        ref[64 * k + i] = (uint8_t)(one[i / 8] >> (8 * (7 - i % 8)));
    }
    HT(sha512_x4_finalize)(out, h4, buf, total);
    for (k = 0; k < 4; k++) {
      snprintf(what, sizeof what, "diff iter %lu sha512_x4 finalize instance %d total=%llu", iter, k,
               (unsigned long long)total);
      check(what, out + 64 * k, ref + 64 * k, 64);
    }
  }
}

static int run_diff(uint64_t seed, unsigned long iters)
{
  uint8_t *msg = xmalloc(MAXMSG);
  unsigned long i;

  printf("diff seed %llu iterations %lu oracle %s\n", (unsigned long long)seed, iters,
         OpenSSL_version(0));
  g_rng = seed;
  for (i = 0; i < iters; i++) {
    size_t len = rnd_len();
    if (len > MAXMSG)
      len = MAXMSG;
    rnd_bytes(msg, MAXMSG);
    diff_keccak(i, msg, len);
    diff_sha2(i, msg, len);
    diff_compress(i);
    diff_length(i);
    diff_hmac(i, msg, len);
    diff_mgf1(i);
    diff_arrays(i, msg);
    diff_keccak_x4(i);
    diff_sha2_multi(i);
    diff_length_multi(i);
  }
  free(msg);
  return 0;
}

/* ------------------------------------------------------------------ */

/* A command-line number in C notation (decimal, 0x hex or 0 octal). */
static unsigned long long arg_number(const char *s)
{
  char *end;
  unsigned long long n;

  errno = 0;
  n = strtoull(s, &end, 0);
  if (end == s || *end || errno || *s == '-')
    die("bad number", s);
  return n;
}

int main(int argc, char **argv)
{
  if (argc == 3 && !strcmp(argv[1], "cavp"))
    run_cavp(argv[2]);
  else if (argc == 4 && !strcmp(argv[1], "diff"))
    run_diff(arg_number(argv[2]), (unsigned long)arg_number(argv[3]));
  else {
    fprintf(stderr, "usage: %s cavp <dir> | diff <seed> <iterations>\n", argv[0]);
    return 2;
  }
  printf("%s: %lu checks passed, %lu failed\n", argv[1], g_pass, g_fail);
  return g_fail ? 1 : (g_pass ? 0 : 1);
}
