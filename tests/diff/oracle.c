/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * oracle.c
 * ========
 *
 * A line-oriented front end to one implementation, driven by
 * tests/diff/difftest.py. Running each implementation in its own process
 * keeps their symbols apart (several baselines export the same names) and
 * lets one driver compare any pair, including single-set builds.
 *
 * Started as "oracle [--variant=V]"; it first prints "ready <impl> <variant>"
 * (or "unavailable ..." and exits when the variant cannot run here).
 *
 * Requests on stdin, one per line; one response line each on stdout:
 *
 *   keygen <set> <skseed> <skprf> <pkseed>          ok <pk> <sk>
 *   sign   <set> <iface> <ph> <sk> <msg> <ctx> <addrnd>   ok <sig>
 *   verify <set> <iface> <ph> <pk> <msg> <ctx> <sig>      ok accept|reject
 *
 * or "unsupported" or "error". <iface> is internal or external; <ph> is
 * none, an ACVP hash name, or "-" for internal calls. A byte string is
 * written "x" followed by its hex digits ("x" alone is empty); "-" marks an
 * absent value (no context on the internal interface; no addrnd for
 * deterministic signing).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "impl.h"

#define MAX_TOKENS 9

typedef struct {
    uint8_t *p;
    size_t len;
    int present;
} bytes;

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Returns 0 on success; -1 for a malformed field. */
static int decode(const char *s, bytes *b)
{
    size_t len;

    b->p = NULL, b->len = 0, b->present = 0;
    if (strcmp(s, "-") == 0)
        return 0;
    if (s[0] != 'x')
        return -1;
    s++;
    len = strlen(s);
    if (len % 2)
        return -1;
    b->present = 1;
    b->len = len / 2;
    b->p = malloc(b->len ? b->len : 1);
    if (b->p == NULL)
        return -1;
    for (size_t i = 0; i < b->len; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        b->p[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

static void put_hex(const uint8_t *p, size_t len)
{
    static const char digits[] = "0123456789abcdef";

    putchar(' ');
    putchar('x');
    for (size_t i = 0; i < len; i++) {
        putchar(digits[p[i] >> 4]);
        putchar(digits[p[i] & 15]);
    }
}

static void status_line(int st)
{
    puts(st == IMPL_UNSUPPORTED ? "unsupported" : "error");
}

static int parse_iface_ph(const char *iface, const char *ph, int *internal, int *phi)
{
    if (strcmp(iface, "internal") == 0) {
        *internal = 1;
        *phi = PH_NONE;
        return strcmp(ph, "-") == 0 ? 0 : -1;
    }
    if (strcmp(iface, "external") != 0)
        return -1;
    *internal = 0;
    *phi = slh_ph_index(ph);
    return *phi < 0 ? -1 : 0;
}

static void handle(char **tok, int ntok)
{
    int set, internal, ph, st, nb;
    bytes b[5] = { { 0 } };
    const slh_set *s;

    /* Every malformed request ends at "bad": free what was decoded, answer badrequest. */
    if (ntok < 2 || (set = slh_set_index(tok[1])) < 0)
        goto bad;
    s = &slh_sets[set];

    if (strcmp(tok[0], "keygen") == 0 && ntok == 5) {
        uint8_t pk[64], sk[128];
        for (nb = 0; nb < 3; nb++)
            if (decode(tok[2 + nb], &b[nb]) || !b[nb].present || b[nb].len != s->n)
                goto bad;
        st = impl_keygen_seed(set, b[0].p, b[1].p, b[2].p, pk, sk);
        if (st != IMPL_OK) {
            status_line(st);
        } else {
            fputs("ok", stdout);
            put_hex(pk, s->pk_bytes);
            put_hex(sk, s->sk_bytes);
            putchar('\n');
        }
    } else if (strcmp(tok[0], "sign") == 0 && ntok == 8) {
        uint8_t *sig;
        if (parse_iface_ph(tok[2], tok[3], &internal, &ph))
            goto bad;
        for (nb = 0; nb < 4; nb++)
            if (decode(tok[4 + nb], &b[nb]))
                goto bad;
        /* sk, msg required; ctx only on external; addrnd optional, n bytes. */
        if (!b[0].present || b[0].len != s->sk_bytes || !b[1].present ||
            b[2].present == internal || (b[3].present && b[3].len != s->n))
            goto bad;
        sig = malloc(s->sig_bytes);
        if (sig == NULL)
            goto bad;
        st = internal ? impl_sign_internal(set, b[0].p, b[1].p, b[1].len, b[3].p, sig)
                      : impl_sign(set, (slh_ph)ph, b[0].p, b[1].p, b[1].len, b[2].p,
                                  b[2].len, b[3].p, sig);
        if (st != IMPL_OK) {
            status_line(st);
        } else {
            fputs("ok", stdout);
            put_hex(sig, s->sig_bytes);
            putchar('\n');
        }
        free(sig);
    } else if (strcmp(tok[0], "verify") == 0 && ntok == 8) {
        if (parse_iface_ph(tok[2], tok[3], &internal, &ph))
            goto bad;
        for (nb = 0; nb < 4; nb++)
            if (decode(tok[4 + nb], &b[nb]))
                goto bad;
        if (!b[0].present || b[0].len != s->pk_bytes || !b[1].present ||
            b[2].present == internal || !b[3].present)
            goto bad;
        st = internal ? impl_verify_internal(set, b[0].p, b[1].p, b[1].len, b[3].p,
                                             b[3].len)
                      : impl_verify(set, (slh_ph)ph, b[0].p, b[1].p, b[1].len, b[2].p,
                                    b[2].len, b[3].p, b[3].len);
        if (st == IMPL_OK)
            puts("ok accept");
        else if (st == IMPL_REJECT)
            puts("ok reject");
        else
            status_line(st);
    } else {
        goto bad;
    }
    for (int i = 0; i < 5; i++)
        free(b[i].p);
    return;
bad:
    for (int i = 0; i < 5; i++)
        free(b[i].p);
    puts("badrequest");
}

int main(int argc, char **argv)
{
    char *line = NULL;
    size_t cap = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--variant=", 10) != 0) {
            fprintf(stderr, "usage: oracle [--variant=V]\n");
            return 2;
        }
        if (impl_force_variant(argv[i] + 10) != IMPL_OK) {
            printf("unavailable %s %s\n", impl_name(), argv[i] + 10);
            return 3;
        }
    }
    if (slh_tables_check() != 0 || impl_init() != IMPL_OK) {
        fprintf(stderr, "oracle: %s failed to initialise\n", impl_name());
        return 2;
    }
    printf("ready %s %s\n", impl_name(), impl_variant());
    fflush(stdout);
    while (getline(&line, &cap, stdin) > 0) {
        char *tok[MAX_TOKENS], *save = NULL;
        int ntok = 0;
        for (char *t = strtok_r(line, " \n", &save); t && ntok < MAX_TOKENS;
             t = strtok_r(NULL, " \n", &save))
            tok[ntok++] = t;
        handle(tok, ntok);
        fflush(stdout);
    }
    free(line);
    return 0;
}
