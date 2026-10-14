# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# difftest.py
# ===========
#
# Differential testing of two SLH-DSA implementations, each running as a
# tests/diff/oracle process. Both receive the same inputs, derived from a
# recorded seed, and every output is compared byte for byte:
#
#   keygen   slh_keygen_internal from (SK.seed, SK.prf, PK.seed)
#   sign     deterministic and hedged (fixed addrnd), internal and external,
#            pure and every pre-hash function, with edge and random
#            message and context lengths
#   verify   the signature (must be accepted by both) and four corrupted
#            forms: one flipped signature bit, a changed message, a changed
#            context (external only) and a signature one byte short (all
#            must be rejected by both)
#
# Inputs come from SHAKE-256 over a fixed label, the seed, the parameter set
# and the case number, so any case is reproduced from those three values
# alone (--seed, --sets, --first/--count). A mismatch prints that triple and
# the request that diverged.
#
# Case i of a set takes combination i modulo 28 of (interface, pre-hash,
# signing mode): internal deterministic and hedged, then external with no
# pre-hash and each of the twelve pre-hash functions, deterministic and
# hedged. --count 28 therefore covers every combination once per set.
#
# An oracle command may contain {set} (e.g. SLH-DSA-SHA2-128f) and
# {params} (e.g. sphincs-sha2-128f) for implementations built per set.
# A combination one side does not support is counted NOT RUN, never as
# agreement. When only one side can sign a case (an implementation that
# signs only with its own randomness), the other side's signature is still
# put through both verifiers and the case counts as verify_only.
#
# Verdict: FAIL on any mismatch (exit 1); INCOMPLETE when a case was not run
# in full (exit 3); PASS-RESTRICTED when everything run agreed but the run
# left out parameter sets or the pre-hash combinations, or reached fewer
# than all combinations per set (exit 4); INCONCLUSIVE when an oracle did
# not answer in time (exit 5); PASS otherwise (exit 0). INCOMPLETE and
# PASS-RESTRICTED are not PASS: read the verdict as a whole token.
#
# --prehash=no limits the combinations to the four without a pre-hash
# function (for implementations that lack HashSLH-DSA); the verdict line
# then says scope=no-prehash, and --count=4 covers them once per set.
#
# Agreement establishes byte equality of the two implementations on the
# inputs run, nothing more. Two independent codebases agreeing makes a
# shared misreading of FIPS 205 less likely but does not exclude it; the
# ACVP vectors are the external reference.
#
# Every request must be written and its reply arrive within --timeout
# seconds (default 600); a miss ends the run INCONCLUSIVE (exit 5), naming
# the case. At the end every oracle must exit with status 0 within the same
# timeout once its input is closed; one that has to be killed, or exits
# otherwise, also makes the run INCONCLUSIVE (exit 5), naming the oracle.
#
# Negative controls corrupt the second oracle's replies; the run must then
# report mismatches. --control=corrupt-b flips one bit of every signature,
# corrupt-b-keygen one bit of every public key, and corrupt-b-verify turns
# every verification decision into its opposite, so that each of the three
# comparisons is shown to detect a wrong answer.
#
# A case counts NOT RUN only when a side answers `unsupported` and the
# other side succeeded or is unsupported too; an unsupported request
# against an error on the other side is a mismatch, not a gap.
#
# Usage:
#   difftest.py --a=CMD --b=CMD --seed=N [--count=28] [--first=0]
#               [--sets=A,B|all] [--prehash=yes|no]
#               [--control=corrupt-b|corrupt-b-keygen|corrupt-b-verify]
#               [--timeout=S] [--log=FILE]

import hashlib
import os
import select
import shlex
import subprocess
import sys
import time

REPLY_TIMEOUT = 600.0  # seconds per oracle reply; --timeout overrides

SETS = [
    ("SLH-DSA-SHA2-128s", 16, 64), ("SLH-DSA-SHAKE-128s", 16, 64),
    ("SLH-DSA-SHA2-128f", 16, 64), ("SLH-DSA-SHAKE-128f", 16, 64),
    ("SLH-DSA-SHA2-192s", 24, 96), ("SLH-DSA-SHAKE-192s", 24, 96),
    ("SLH-DSA-SHA2-192f", 24, 96), ("SLH-DSA-SHAKE-192f", 24, 96),
    ("SLH-DSA-SHA2-256s", 32, 128), ("SLH-DSA-SHAKE-256s", 32, 128),
    ("SLH-DSA-SHA2-256f", 32, 128), ("SLH-DSA-SHAKE-256f", 32, 128),
]
PREHASH = ["SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224",
           "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
           "SHAKE-128", "SHAKE-256"]
COMBOS = ([("internal", "-", det) for det in (True, False)] +
          [("external", ph, det) for ph in ["none"] + PREHASH for det in (True, False)])
# Lengths around SHA-256, SHA-512 and SHAKE block boundaries, plus extremes.
EDGE_MSG = [0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 111, 112, 119, 127, 128,
            135, 136, 137, 167, 168, 169, 255, 256, 1023, 1024, 4096]
EDGE_CTX = [0, 1, 2, 127, 128, 254, 255]
LABEL = b"nirapod-slhdsa difftest v1"


class Stream:
    """Deterministic byte stream: SHAKE-256(label || seed || set || case)."""

    def __init__(self, seed, setname, case):
        h = hashlib.shake_256()
        h.update(LABEL + seed.to_bytes(8, "big") + setname.encode() + b"\0" +
                 case.to_bytes(8, "big"))
        self.buf = h.digest(1 << 16)
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.buf):
            raise RuntimeError("stream exhausted")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def below(self, bound):
        return int.from_bytes(self.take(4), "big") % bound


class Timeout(Exception):
    pass


class Oracle:
    """One oracle process; every reply must arrive within REPLY_TIMEOUT s."""

    def __init__(self, cmd):
        self.cmd = cmd
        self.buf = b""
        try:
            self.proc = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE)
        except OSError as e:
            raise SystemExit(f"difftest: cannot start oracle {cmd!r}: {e}")
        hello = self.readline().split()
        if not hello or hello[0] != "ready":
            raise SystemExit(f"difftest: oracle did not start: {cmd!r}: {hello}")
        self.name = " ".join(hello[1:])

    def readline(self):
        fd = self.proc.stdout.fileno()
        deadline = time.monotonic() + REPLY_TIMEOUT
        while b"\n" not in self.buf:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                raise Timeout(f"no reply from {self.cmd!r} within {REPLY_TIMEOUT}s")
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                raise SystemExit(f"difftest: oracle exited: {self.cmd!r}")
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        return line.decode()

    def ask(self, line):
        """Write the request without blocking past the deadline, then read."""
        fd = self.proc.stdin.fileno()
        data = (line + "\n").encode()
        deadline = time.monotonic() + REPLY_TIMEOUT
        os.set_blocking(fd, False)
        try:
            while data:
                left = deadline - time.monotonic()
                if left <= 0 or not select.select([], [fd], [], left)[1]:
                    raise Timeout(f"{self.cmd!r} did not take a request within {REPLY_TIMEOUT}s")
                try:
                    data = data[os.write(fd, data):]
                except BlockingIOError:
                    pass
        except BrokenPipeError:
            raise SystemExit(f"difftest: oracle exited: {self.cmd!r}")
        finally:
            os.set_blocking(fd, True)
        return self.readline().split()

    def close(self, kill=False):
        """
        Close stdin and wait, within the timeout; kill on expiry or request.
        Returns None after a clean exit (status 0), else what went wrong.
        """
        if not kill:
            try:
                self.proc.stdin.close()
                rc = self.proc.wait(timeout=REPLY_TIMEOUT)
                return None if rc == 0 else f"{self.cmd!r} exited with status {rc}"
            except subprocess.TimeoutExpired:
                problem = f"{self.cmd!r} did not exit within {REPLY_TIMEOUT}s of closing"
            except OSError as e:
                problem = f"{self.cmd!r} could not be closed: {e}"
        else:
            problem = "killed"
        self.proc.kill()
        self.proc.wait()
        return problem


# The control that corrupts B's reply at each step (--control=corrupt-b...).
CONTROL_STEP = {"keygen": "-keygen", "sign": "", "verify": "-verify"}


def gap(ra, rb):
    """A NOT RUN case: a side cannot do the request, and neither side failed."""
    return ("unsupported" in (ra[0], rb[0])
            and all(x[0] in ("ok", "unsupported") for x in (ra, rb)))


def hx(b):
    return "x" + b.hex()


def params_token(setname):
    return "sphincs-" + setname[len("SLH-DSA-"):].lower()


class Runner:
    def __init__(self, cmd_a, cmd_b, control, log):
        self.cmds = (cmd_a, cmd_b)
        self.pool = {}
        self.control = control
        self.log = log

    def oracle(self, side, setname):
        cmd = self.cmds[side].replace("{set}", setname).replace("{params}", params_token(setname))
        if cmd not in self.pool:
            self.pool[cmd] = Oracle(cmd)
        return self.pool[cmd]

    def both(self, setname, line, step):
        """The replies of A and B to line; under a control, B's corrupted."""
        ra = self.oracle(0, setname).ask(line)
        rb = self.oracle(1, setname).ask(line)
        if rb[0] == "ok" and self.control == f"corrupt-b{CONTROL_STEP[step]}":
            if step == "verify":
                rb = ["ok", "reject" if rb[1] == "accept" else "accept"]
            else:
                b = bytearray.fromhex(rb[1][1:])
                b[len(b) // 3] ^= 0x10
                rb = ["ok", hx(bytes(b))] + rb[2:]
        return ra, rb

    def close(self, kill=False):
        """Close every oracle; the problems of those that did not exit cleanly."""
        return [p for p in (o.close(kill) for o in self.pool.values()) if p]


def run_case(r, seed, setname, n, case, stats, combos):
    st = Stream(seed, setname, case)
    iface, ph, det = combos[case % len(combos)]
    internal = iface == "internal"
    tag = f"seed={seed} set={setname} case={case} iface={iface} ph={ph} det={int(det)}"

    def mismatch(what, line, ra, rb):
        stats["mismatch"] += 1
        ja, jb = " ".join(ra), " ".join(rb)
        at = next((i for i, (x, y) in enumerate(zip(ja, jb)) if x != y), min(len(ja), len(jb)))
        lo = max(0, at - 40)
        msg = (f"MISMATCH {tag} step={what} first difference at reply char {at}\n"
               f"  a: ...{ja[lo:at + 40]}\n  b: ...{jb[lo:at + 40]}")
        print(msg, file=sys.stderr)
        if r.log:
            r.log.write(f"{msg}\n  request: {line}\n")

    seeds = [st.take(n) for _ in range(3)]
    line = f"keygen {setname} {hx(seeds[0])} {hx(seeds[1])} {hx(seeds[2])}"
    ra, rb = r.both(setname, line, "keygen")
    if gap(ra, rb):
        stats["notrun"] += 1
        return
    if ra[0] != "ok" or ra != rb:
        return mismatch("keygen", line, ra, rb)
    pk, sk = bytes.fromhex(ra[1][1:]), bytes.fromhex(ra[2][1:])

    mlen = EDGE_MSG[st.below(len(EDGE_MSG))] if st.below(4) == 0 else st.below(2049)
    msg = st.take(mlen)
    if internal:
        ctx = None
    else:
        clen = EDGE_CTX[st.below(len(EDGE_CTX))] if st.below(4) == 0 else st.below(256)
        ctx = st.take(clen)
    addrnd = None if det else st.take(n)
    ctx_tok = "-" if ctx is None else hx(ctx)
    line = (f"sign {setname} {iface} {ph} {hx(sk)} {hx(msg)} {ctx_tok} "
            f"{'-' if addrnd is None else hx(addrnd)}")
    ra, rb = r.both(setname, line, "sign")
    verify_only = False
    if ra[0] == "unsupported" and rb[0] == "unsupported":
        stats["notrun"] += 1
        return
    if "unsupported" in (ra[0], rb[0]):
        # One side cannot sign this way (e.g. it signs only with its own
        # randomness): verify the other side's signature on both.
        signed = rb if ra[0] == "unsupported" else ra
        if signed[0] != "ok":
            return mismatch("sign", line, ra, rb)
        verify_only = True
        sig = bytes.fromhex(signed[1][1:])
    elif ra[0] != "ok" or ra != rb:
        return mismatch("sign", line, ra, rb)
    else:
        sig = bytes.fromhex(ra[1][1:])

    flipped = bytearray(sig)
    flipped[st.below(len(sig))] ^= 1 << st.below(8)
    other_msg = msg + b"\x00" if mlen == 0 else bytes([msg[0] ^ 0x80]) + msg[1:]
    trials = [("verify", msg, ctx, sig, "accept"),
              ("verify-flipped-sig", msg, ctx, bytes(flipped), "reject"),
              ("verify-other-msg", other_msg, ctx, sig, "reject"),
              ("verify-short-sig", msg, ctx, sig[:-1], "reject")]
    if ctx is not None:
        other_ctx = ctx + b"\x00" if len(ctx) < 255 else ctx[:-1]
        trials.append(("verify-other-ctx", msg, other_ctx, sig, "reject"))
    for what, m, c, s, want in trials:
        ctx_tok = "-" if c is None else hx(c)
        line = f"verify {setname} {iface} {ph} {hx(pk)} {hx(m)} {ctx_tok} {hx(s)}"
        ra, rb = r.both(setname, line, "verify")
        if gap(ra, rb):
            stats["notrun"] += 1
            return
        if ra != rb or ra != ["ok", want]:
            return mismatch(what, line, ra, rb)
    stats["verify_only" if verify_only else "agree"] += 1


def main(argv):
    opts = {}
    global REPLY_TIMEOUT
    known = {"a", "b", "seed", "count", "first", "sets", "prehash", "control", "log", "timeout"}
    for a in argv[1:]:
        k, _, v = a[2:].partition("=")
        if not a.startswith("--") or not _ or k not in known:
            print("usage: difftest.py --a=CMD --b=CMD --seed=N [--count=N] [--first=N]\n"
                  "       [--sets=A,B|all] [--prehash=yes|no] [--control=corrupt-b[-keygen|-verify]]\n"
                  "       [--timeout=S] "
                  "[--log=FILE]",
                  file=sys.stderr)
            return 2
        opts[k] = v
    if "a" not in opts or "b" not in opts or "seed" not in opts:
        print("difftest: --a, --b and --seed are required", file=sys.stderr)
        return 2
    seed = int(opts["seed"], 0)
    REPLY_TIMEOUT = float(opts.get("timeout", REPLY_TIMEOUT))
    first = int(opts.get("first", 0))
    control = opts.get("control", "none")
    if opts.get("prehash", "yes") not in ("yes", "no"):
        print("difftest: --prehash takes yes or no", file=sys.stderr)
        return 2
    combos = COMBOS if opts.get("prehash", "yes") == "yes" else COMBOS[:4]
    count = int(opts.get("count", len(combos)))
    if control not in ("none", "corrupt-b", "corrupt-b-keygen", "corrupt-b-verify"):
        print(f"difftest: unknown control {control}", file=sys.stderr)
        return 2
    wanted = opts.get("sets", "all")
    sets = SETS if wanted == "all" else [s for s in SETS if s[0] in wanted.split(",")]
    if wanted != "all" and len(sets) != len(wanted.split(",")):
        print("difftest: unknown parameter set in --sets", file=sys.stderr)
        return 2
    log = open(opts["log"], "a") if "log" in opts else None

    r = Runner(opts["a"], opts["b"], control, log)
    total = {"agree": 0, "verify_only": 0, "mismatch": 0, "notrun": 0}
    for setname, n, _ in sets:
        stats = {"agree": 0, "verify_only": 0, "mismatch": 0, "notrun": 0}
        for case in range(first, first + count):
            try:
                run_case(r, seed, setname, n, case, stats, combos)
            except Timeout as e:
                r.close(kill=True)
                print(f"difftest: {e}; seed={seed} set={setname} case={case} "
                      f"verdict=INCONCLUSIVE", flush=True)
                return 5
        a = r.oracle(0, setname).name
        b = r.oracle(1, setname).name
        print(f"diff set={setname} a=[{a}] b=[{b}] seed={seed} cases={first}..{first + count - 1} "
              f"agree={stats['agree']} verify_only={stats['verify_only']} "
              f"mismatch={stats['mismatch']} notrun={stats['notrun']}",
              flush=True)
        for k in total:
            total[k] += stats[k]
    problems = r.close()
    if problems:
        print(f"difftest: oracle not closed cleanly: {'; '.join(problems)}; seed={seed} "
              f"verdict=INCONCLUSIVE", flush=True)
        return 5
    restricted = wanted != "all" or combos is not COMBOS or count < len(combos)
    verdict = ("FAIL" if total["mismatch"] else
               "INCOMPLETE" if total["notrun"] or total["verify_only"] or not total["agree"]
               else "PASS-RESTRICTED" if restricted else "PASS")
    scope = " scope=no-prehash" if combos is not COMBOS else ""
    print(f"difftest: control={control}{scope} seed={seed} agree={total['agree']} "
          f"verify_only={total['verify_only']} mismatch={total['mismatch']} "
          f"notrun={total['notrun']} verdict={verdict}")
    if log:
        log.close()
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3, "PASS-RESTRICTED": 4}[verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
