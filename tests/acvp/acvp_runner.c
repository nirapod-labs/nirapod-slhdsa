/*
 * SPDX-FileCopyrightText: nirapod-slhdsa contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * acvp_runner.c
 * =============
 *
 * Runs the NIST ACVP SLH-DSA vectors against the implementation linked
 * through tests/diff/adapters/impl.h.
 *
 * Input chain: tests/vectors/acvp/acvp.lock pins the ACVP-Server commit
 * and the SHA-256 of each JSON file; tests/vectors/fetch-acvp.py refuses
 * any other bytes; tests/acvp/convert.py joins prompts with expected
 * results and refuses any case it cannot place. This runner reads the
 * converted flat files and trusts their identity to that chain; it refuses
 * a line with a repeated field, checks every field it uses for presence,
 * the test numbers for decimal form, byte strings for hex form and the
 * length their parameter set requires, and stops with status 2 on the
 * first malformed line.
 *
 *   keyGen  slh_keygen_internal from (SK.seed, SK.prf, PK.seed); PK and SK
 *           must equal the expected bytes.
 *   sigGen  the signature must equal the expected bytes, and the
 *           implementation's own verifier must accept it.
 *   sigVer  the accept or reject decision must equal testPassed. NIST's
 *           cases include signatures one byte short and one byte long.
 *
 * A PASS establishes byte-exact agreement with NIST's expected results on
 * exactly the cases run, for the implementation and variant named in the
 * verdict line. It says nothing about other inputs, about timing or memory
 * behaviour, or about NIST's vectors themselves; those need the
 * differential, negative and analysis checks.
 *
 * Verdict, in this order of precedence:
 *
 *   FAIL             some case ran and did not match (exit 1)
 *   INCOMPLETE       no case failed, but some case was NOT RUN because the
 *                    implementation does not support it, or nothing ran
 *                    (exit 3)
 *   PASS-RESTRICTED  every case run matched, but the run did not cover the
 *                    whole published set: --sets or --prehash=no left cases
 *                    out (counted as filtered), or one of the keyGen,
 *                    sigGen and sigVer files was not given (exit 4)
 *   PASS             every case of the keyGen, sigGen and sigVer files
 *                    given ran and matched, nothing filtered (exit 0).
 *                    The runner cannot tell whether those files hold
 *                    every published case: convert.py's strict join of
 *                    prompts and expected results is what ensures that,
 *                    and CI also holds the case count to its minimum
 *                    (ci/rules/test-acvp.toml)
 *
 * In the status vocabulary of the project, INCOMPLETE means "no FAIL, and
 * NOT RUN for part of the cases", and PASS-RESTRICTED means "PASS on the
 * cases run, NOT RUN on the rest by choice". Neither is a PASS: read the
 * verdict as a whole token (or the exit status), never as a prefix.
 *
 * A case that runs longer than --timeout seconds (default 600) ends the
 * run with INCONCLUSIVE (exit 5) and the case named; nothing after it runs.
 *
 * --variant forces one code path of an implementation that has several
 * (see impl_force_variant); the variant in use is printed with the verdict.
 *
 * Negative controls (--control) deliberately break one step so that a
 * harness which cannot detect that break is itself detected:
 *
 *   flip-output    flip one bit of the computed PK, SK or signature, or
 *                  invert the computed verify decision, before comparison
 *   flip-expected  flip one bit of the expected value, or invert testPassed
 *   mutate-input   flip one bit of the message (keyGen: of PK.seed) before
 *                  the implementation sees it
 *
 * tests/acvp/controls.py runs each control and checks that the expected
 * cases fail; tests/acvp/verdicts.py checks the verdict rules above. Exit
 * status: 0 PASS, 1 FAIL, 2 usage or input error, 3 INCOMPLETE (or the
 * requested variant cannot run here: NOT RUN), 4 PASS-RESTRICTED,
 * 5 INCONCLUSIVE (timeout).
 */

#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "impl.h"

enum control { CTL_NONE, CTL_FLIP_OUTPUT, CTL_FLIP_EXPECTED, CTL_MUTATE_INPUT };
enum outcome { OUT_PASS, OUT_FAIL, OUT_NOT_RUN };

#define MAX_FIELDS 16

typedef struct {
    char *key[MAX_FIELDS];
    char *val[MAX_FIELDS];
    int count;
} fields;

typedef struct {
    uint8_t *p;
    size_t len;
    int present;
} bytes;

typedef struct {
    char mode[8];
    long tg;
    char set[24];
    char iface[10];
    char ph[16];
    char det[4];
    long cases, pass, fail, notrun;
} group_stat;

static enum control control = CTL_NONE;
static const char *variant = NULL;
static int set_selected[SLH_SET_COUNT];
static int restricted = 0;
static int skip_prehash = 0;
static int verbose = 0;

/*
 * Per-case time limit. A call that hangs must not leave the run without a
 * verdict, and must not be mistaken for anything else: on expiry the runner
 * prints INCONCLUSIVE naming the case and exits 5. Only async-signal-safe
 * calls are made from the handler.
 */
static unsigned case_timeout = 600;
static char timeout_msg[160];

static void on_timeout(int sig)
{
    (void)sig;
    if (write(STDOUT_FILENO, timeout_msg, strlen(timeout_msg)) < 0)
        _exit(5);
    _exit(5);
}

static void die(const char *msg, const char *detail)
{
    fprintf(stderr, "acvp: %s%s%s\n", msg, detail ? ": " : "", detail ? detail : "");
    exit(2);
}

static int split_fields(char *line, fields *f)
{
    char *save = NULL;

    f->count = 0;
    for (char *tok = strtok_r(line, " \n", &save); tok != NULL;
         tok = strtok_r(NULL, " \n", &save)) {
        char *eq = strchr(tok, '=');
        if (f->count == MAX_FIELDS)
            return -1;
        if (eq != NULL)
            *eq = '\0';
        for (int i = 0; i < f->count; i++)
            if (strcmp(f->key[i], tok) == 0)
                return -1;
        if (eq == NULL) {
            f->key[f->count] = tok;
            f->val[f->count] = NULL;
        } else {
            f->key[f->count] = tok;
            f->val[f->count] = eq + 1;
        }
        f->count++;
    }
    return 0;
}

static const char *get(const fields *f, const char *key)
{
    for (int i = 0; i < f->count; i++)
        if (strcmp(f->key[i], key) == 0)
            return f->val[i];
    return NULL;
}

static const char *need(const fields *f, const char *key)
{
    const char *v = get(f, key);
    if (v == NULL)
        die("missing field", key);
    return v;
}

/* A test or group number: decimal digits only, at most nine of them. */
static long need_number(const fields *f, const char *key)
{
    const char *v = need(f, key);
    size_t len = strlen(v);

    if (len == 0 || len > 9 || strspn(v, "0123456789") != len)
        die("malformed number", key);
    return strtol(v, NULL, 10);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

/* Decodes an optional hex field; malformed hex is an input error. */
static bytes hex_field(const fields *f, const char *key)
{
    bytes b = { NULL, 0, 0 };
    const char *s = get(f, key);
    size_t len;

    if (s == NULL)
        return b;
    len = strlen(s);
    if (len % 2 != 0)
        die("odd-length hex", key);
    b.present = 1;
    b.len = len / 2;
    b.p = malloc(b.len ? b.len : 1);
    if (b.p == NULL)
        die("out of memory", NULL);
    for (size_t i = 0; i < b.len; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            die("bad hex", key);
        b.p[i] = (uint8_t)(hi << 4 | lo);
    }
    return b;
}

static bytes need_hex(const fields *f, const char *key, size_t want)
{
    bytes b = hex_field(f, key);
    if (!b.present)
        die("missing field", key);
    if (want != (size_t)-1 && b.len != want)
        die("field has the wrong length for its parameter set", key);
    return b;
}

static void flip_bit(uint8_t *p, size_t len)
{
    if (len > 0)
        p[len / 2] ^= 0x01;
}

/* Mutating an empty message means appending a byte: return a new buffer. */
static bytes mutate_message(bytes m)
{
    if (m.len == 0) {
        free(m.p);
        m.p = malloc(1);
        if (m.p == NULL)
            die("out of memory", NULL);
        m.p[0] = 0x01;
        m.len = 1;
    } else {
        flip_bit(m.p, m.len);
    }
    return m;
}

static enum outcome from_status(int st)
{
    return st == IMPL_UNSUPPORTED ? OUT_NOT_RUN : OUT_FAIL;
}

static enum outcome run_keygen(const fields *f, int set)
{
    const slh_set *s = &slh_sets[set];
    bytes sk_seed = need_hex(f, "skSeed", s->n), sk_prf = need_hex(f, "skPrf", s->n);
    bytes pk_seed = need_hex(f, "pkSeed", s->n);
    bytes pk_exp = need_hex(f, "pk", s->pk_bytes), sk_exp = need_hex(f, "sk", s->sk_bytes);
    uint8_t pk[64], sk[128];
    enum outcome out;
    int st;

    if (control == CTL_MUTATE_INPUT)
        flip_bit(pk_seed.p, pk_seed.len);
    if (control == CTL_FLIP_EXPECTED)
        flip_bit(pk_exp.p, pk_exp.len);
    st = impl_keygen_seed(set, sk_seed.p, sk_prf.p, pk_seed.p, pk, sk);
    if (st != IMPL_OK) {
        out = from_status(st);
    } else {
        if (control == CTL_FLIP_OUTPUT)
            flip_bit(pk, s->pk_bytes);
        out = memcmp(pk, pk_exp.p, s->pk_bytes) == 0 &&
                      memcmp(sk, sk_exp.p, s->sk_bytes) == 0
                  ? OUT_PASS
                  : OUT_FAIL;
    }
    free(sk_seed.p), free(sk_prf.p), free(pk_seed.p), free(pk_exp.p), free(sk_exp.p);
    return out;
}

static enum outcome run_siggen(const fields *f, int set, int internal, int ph)
{
    const slh_set *s = &slh_sets[set];
    int det = strcmp(need(f, "det"), "1") == 0;
    bytes sk = need_hex(f, "sk", s->sk_bytes), msg = need_hex(f, "msg", (size_t)-1);
    bytes ctx = internal ? (bytes){ NULL, 0, 0 } : need_hex(f, "ctx", (size_t)-1);
    bytes addrnd = det ? (bytes){ NULL, 0, 0 } : need_hex(f, "addrnd", s->n);
    bytes exp = need_hex(f, "sig", s->sig_bytes);
    uint8_t *sig = malloc(s->sig_bytes);
    const uint8_t *pk = sk.p + 2 * s->n; /* SK = SK.seed || SK.prf || PK */
    enum outcome out;
    int st;

    if (sig == NULL)
        die("out of memory", NULL);
    if (det != (get(f, "addrnd") == NULL))
        die("det flag and addrnd field disagree", NULL);
    if (control == CTL_MUTATE_INPUT)
        msg = mutate_message(msg);
    if (control == CTL_FLIP_EXPECTED)
        flip_bit(exp.p, exp.len);

    if (internal)
        st = impl_sign_internal(set, sk.p, msg.p, msg.len, addrnd.p, sig);
    else
        st = impl_sign(set, (slh_ph)ph, sk.p, msg.p, msg.len, ctx.p, ctx.len,
                       addrnd.p, sig);
    if (st != IMPL_OK) {
        out = from_status(st);
    } else {
        /* The implementation must also accept its own signature. */
        int v = internal
                    ? impl_verify_internal(set, pk, msg.p, msg.len, sig, s->sig_bytes)
                    : impl_verify(set, (slh_ph)ph, pk, msg.p, msg.len, ctx.p,
                                  ctx.len, sig, s->sig_bytes);
        if (control == CTL_FLIP_OUTPUT)
            flip_bit(sig, s->sig_bytes);
        out = v == IMPL_OK && memcmp(sig, exp.p, s->sig_bytes) == 0 ? OUT_PASS
                                                                    : OUT_FAIL;
    }
    free(sig), free(sk.p), free(msg.p), free(ctx.p), free(addrnd.p), free(exp.p);
    return out;
}

static enum outcome run_sigver(const fields *f, int set, int internal, int ph)
{
    const slh_set *s = &slh_sets[set];
    bytes pk = need_hex(f, "pk", s->pk_bytes), msg = need_hex(f, "msg", (size_t)-1);
    bytes ctx = internal ? (bytes){ NULL, 0, 0 } : need_hex(f, "ctx", (size_t)-1);
    bytes sig = need_hex(f, "sig", (size_t)-1); /* lengths vary on purpose */
    const char *pass = need(f, "pass");
    int expect_valid, got_valid, st;
    enum outcome out;

    if (strcmp(pass, "1") != 0 && strcmp(pass, "0") != 0)
        die("bad pass field", pass);
    expect_valid = pass[0] == '1';
    if (control == CTL_MUTATE_INPUT)
        msg = mutate_message(msg);
    if (control == CTL_FLIP_EXPECTED)
        expect_valid = !expect_valid;

    if (internal)
        st = impl_verify_internal(set, pk.p, msg.p, msg.len, sig.p, sig.len);
    else
        st = impl_verify(set, (slh_ph)ph, pk.p, msg.p, msg.len, ctx.p, ctx.len,
                         sig.p, sig.len);
    if (st == IMPL_OK || st == IMPL_REJECT) {
        got_valid = st == IMPL_OK;
        if (control == CTL_FLIP_OUTPUT)
            got_valid = !got_valid;
        out = got_valid == expect_valid ? OUT_PASS : OUT_FAIL;
    } else {
        out = from_status(st);
    }
    free(pk.p), free(msg.p), free(ctx.p), free(sig.p);
    return out;
}

static void parse_sets(const char *arg)
{
    char *copy = strdup(arg), *save = NULL;

    if (copy == NULL)
        die("out of memory", NULL);
    restricted = 1;
    for (char *t = strtok_r(copy, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        int i = slh_set_index(t);
        if (i < 0)
            die("unknown parameter set", t);
        set_selected[i] = 1;
    }
    free(copy);
}

static group_stat *find_group(group_stat **groups, size_t *ngroups, size_t *cap,
                              const char *mode, long tg, const fields *f)
{
    group_stat *g;
    const char *v;

    for (size_t i = 0; i < *ngroups; i++)
        if ((*groups)[i].tg == tg && strcmp((*groups)[i].mode, mode) == 0)
            return &(*groups)[i];
    if (*ngroups == *cap) {
        *cap = *cap ? 2 * *cap : 64;
        *groups = realloc(*groups, *cap * sizeof **groups);
        if (*groups == NULL)
            die("out of memory", NULL);
    }
    g = &(*groups)[(*ngroups)++];
    memset(g, 0, sizeof *g);
    snprintf(g->mode, sizeof g->mode, "%s", mode);
    g->tg = tg;
    snprintf(g->set, sizeof g->set, "%s", need(f, "set"));
    snprintf(g->iface, sizeof g->iface, "%s", (v = get(f, "iface")) ? v : "-");
    snprintf(g->ph, sizeof g->ph, "%s", (v = get(f, "ph")) ? v : "-");
    snprintf(g->det, sizeof g->det, "%s", (v = get(f, "det")) ? v : "-");
    return g;
}

int main(int argc, char **argv)
{
    long cases = 0, pass = 0, fail = 0, notrun = 0, filtered = 0;
    int seen_keygen = 0, seen_siggen = 0, seen_sigver = 0;
    group_stat *groups = NULL;
    size_t ngroups = 0, cap = 0;
    int nfiles = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strncmp(a, "--control=", 10) == 0) {
            const char *c = a + 10;
            if (strcmp(c, "none") == 0)
                control = CTL_NONE;
            else if (strcmp(c, "flip-output") == 0)
                control = CTL_FLIP_OUTPUT;
            else if (strcmp(c, "flip-expected") == 0)
                control = CTL_FLIP_EXPECTED;
            else if (strcmp(c, "mutate-input") == 0)
                control = CTL_MUTATE_INPUT;
            else
                die("unknown control", c);
        } else if (strncmp(a, "--sets=", 7) == 0) {
            parse_sets(a + 7);
        } else if (strncmp(a, "--variant=", 10) == 0) {
            variant = a + 10;
        } else if (strncmp(a, "--timeout=", 10) == 0) {
            case_timeout = (unsigned)strtoul(a + 10, NULL, 10);
            if (case_timeout == 0)
                die("--timeout takes a positive number of seconds", NULL);
        } else if (strcmp(a, "--prehash=no") == 0) {
            skip_prehash = 1;
        } else if (strcmp(a, "-v") == 0) {
            verbose = 1;
        } else if (a[0] == '-') {
            die("unknown option", a);
        }
    }

    signal(SIGALRM, on_timeout);
    if (variant != NULL && impl_force_variant(variant) != IMPL_OK) {
        printf("acvp: impl=%s variant=%s verdict=NOT RUN (variant not available)\n",
               impl_name(), variant);
        return 3;
    }
    if (slh_tables_check() != 0)
        die("parameter-set table is inconsistent", NULL);
    if (impl_init() != IMPL_OK)
        die("implementation failed to initialise", impl_name());

    for (int i = 1; i < argc; i++) {
        FILE *in;
        char *line = NULL;
        size_t linecap = 0;

        if (argv[i][0] == '-')
            continue;
        nfiles++;
        in = fopen(argv[i], "r");
        if (in == NULL)
            die("cannot open", argv[i]);
        while (getline(&line, &linecap, in) > 0) {
            fields f;
            const char *mode;
            long tg, tc;
            int set, internal = 0, ph = PH_NONE;
            enum outcome out = OUT_FAIL;
            group_stat *g;

            if (split_fields(line, &f) != 0 || f.count == 0)
                die("malformed line", argv[i]);
            mode = f.key[0];
            tg = need_number(&f, "tg");
            tc = need_number(&f, "tc");
            set = slh_set_index(need(&f, "set"));
            if (set < 0)
                die("unknown parameter set", need(&f, "set"));
            if (strcmp(mode, "keyGen") != 0) {
                const char *iface = need(&f, "iface"), *p = need(&f, "ph");
                if (strcmp(iface, "internal") == 0)
                    internal = 1;
                else if (strcmp(iface, "external") != 0)
                    die("unknown interface", iface);
                if (!internal && (ph = slh_ph_index(p)) < 0)
                    die("unknown pre-hash", p);
            }
            if ((restricted && !set_selected[set]) || (skip_prehash && ph != PH_NONE)) {
                filtered++;
                continue;
            }
            g = find_group(&groups, &ngroups, &cap, mode, tg, &f);

            snprintf(timeout_msg, sizeof timeout_msg,
                     "acvp: timeout after %us in %s tg=%ld tc=%ld verdict=INCONCLUSIVE\n",
                     case_timeout, mode, tg, tc);
            alarm(case_timeout);
            seen_keygen |= strcmp(mode, "keyGen") == 0;
            seen_siggen |= strcmp(mode, "sigGen") == 0;
            seen_sigver |= strcmp(mode, "sigVer") == 0;
            if (strcmp(mode, "keyGen") == 0)
                out = run_keygen(&f, set);
            else if (strcmp(mode, "sigGen") == 0)
                out = run_siggen(&f, set, internal, ph);
            else if (strcmp(mode, "sigVer") == 0)
                out = run_sigver(&f, set, internal, ph);
            else
                die("unknown mode", mode);

            alarm(0);
            cases++, g->cases++;
            if (out == OUT_PASS)
                pass++, g->pass++;
            else if (out == OUT_FAIL)
                fail++, g->fail++;
            else
                notrun++, g->notrun++;
            if (verbose || out == OUT_FAIL)
                fprintf(out == OUT_FAIL ? stderr : stdout, "case %s tg=%ld tc=%ld %s\n",
                        mode, tg, tc,
                        out == OUT_PASS ? "PASS" : out == OUT_FAIL ? "FAIL" : "NOT RUN");
        }
        if (ferror(in))
            die("read error", argv[i]);
        free(line);
        fclose(in);
    }
    if (nfiles == 0)
        die("usage: acvp_runner [--sets=A,B] [--prehash=no] [--variant=V] [--timeout=S] "
            "[--control=...] "
            "[-v] <files>",
            NULL);

    for (size_t i = 0; i < ngroups; i++) {
        const group_stat *g = &groups[i];
        printf("group %s tg=%ld set=%s iface=%s ph=%s det=%s cases=%ld pass=%ld "
               "fail=%ld notrun=%ld\n",
               g->mode, g->tg, g->set, g->iface, g->ph, g->det, g->cases, g->pass,
               g->fail, g->notrun);
    }
    {
        int partial = restricted || skip_prehash || filtered ||
                      !(seen_keygen && seen_siggen && seen_sigver);
        int status = fail ? 1 : (notrun || cases == 0) ? 3 : partial ? 4 : 0;
        const char *verdict = status == 1   ? "FAIL"
                              : status == 3 ? "INCOMPLETE"
                              : status == 4 ? "PASS-RESTRICTED"
                                            : "PASS";
        printf("acvp: impl=%s variant=%s control=%s groups=%zu cases=%ld pass=%ld fail=%ld "
               "notrun=%ld filtered=%ld%s verdict=%s\n",
               impl_name(), impl_variant(),
               control == CTL_NONE           ? "none"
               : control == CTL_FLIP_OUTPUT  ? "flip-output"
               : control == CTL_FLIP_EXPECTED ? "flip-expected"
                                              : "mutate-input",
               ngroups, cases, pass, fail, notrun, filtered,
               restricted || skip_prehash ? " scope=restricted" : "", verdict);
        free(groups);
        return status;
    }
}
