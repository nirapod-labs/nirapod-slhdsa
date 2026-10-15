# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/test_bench.py
# ===================
#
# Checks of the harness's own arithmetic and output rules, on synthetic
# records and fixtures; nothing here is timed:
#
#   python3 -I bench/test_bench.py
#
#   - R pairs rounds: a ratio is formed only within one round, and a
#     constant factor between two implementations gives exactly that R
#     whatever the drift between rounds; a round one side lacks
#     contributes no ratio;
#   - the verdict: the sign-test interval has the expected order
#     statistics, fewer than MIN_ROUNDS rounds are inconclusive, and in a
#     simulation of two implementations of equal speed the rule resolves a
#     comparison in at most 5% of runs, while a 10% difference under the
#     same noise is resolved;
#   - throughput and fault-check ratios use the same pairing;
#   - this library's testing build is never used as a baseline;
#   - the CPU of a Linux AArch64 machine is named from its MIDR fields,
#     or printed by its raw codes, never "unknown";
#   - the working-tree digest matches the commit exactly when the files
#     git does not ignore are unchanged;
#   - the renderer refuses a cell that names a path, labels smoke and
#     trial records, and prints every build's identity;
#   - the code-size reader classes ELF and Mach-O sections.

import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import codesize  # noqa: E402
import host  # noqa: E402
import render  # noqa: E402
import revision  # noqa: E402
import run  # noqa: E402
import stats  # noqa: E402


def obs(name, rnd, ns, s="SLH-DSA-SHA2-128f", op="sign"):
    return dict(name=name, set=s, op=op, round=rnd, status="ok", variant="v", ns=ns)


def ratios(o):
    return stats.ratios(o, "nirapod")


class Ratios(unittest.TestCase):
    def test_pairing_cancels_drift(self):
        # Each round is slower than the last; this library is 0.8 x the
        # baseline within every round.
        o = []
        for r, scale in enumerate([1.0, 1.5, 3.0]):
            o.append(obs("nirapod", r, [80 * scale, 80 * scale]))
            o.append(obs("base", r, [100 * scale, 100 * scale]))
        (row,) = ratios(o)
        self.assertAlmostEqual(row["R"], 0.8)
        self.assertAlmostEqual(row["R_q1"], 0.8)
        self.assertAlmostEqual(row["R_q3"], 0.8)
        self.assertEqual(row["rounds"], 3)
        self.assertIsNone(row["R_low"])
        self.assertEqual(row["verdict"], "inconclusive")   # fewer than MIN_ROUNDS

    def test_unpaired_round_is_left_out(self):
        o = [obs("nirapod", 0, [50]), obs("base", 0, [100]), obs("base", 1, [1])]
        (row,) = ratios(o)
        self.assertEqual(row["rounds"], 1)
        self.assertAlmostEqual(row["R"], 0.5)

    def test_testing_build_is_not_a_baseline(self):
        o = [obs("nirapod", 0, [50]), obs("nirapod-testing", 0, [40])]
        self.assertEqual(ratios(o), [])

    def test_unsupported_is_not_run(self):
        o = [dict(name="boringssl", set="SLH-DSA-SHA2-128f", status="unsupported")]
        self.assertEqual(ratios(o), [])
        self.assertEqual(run.not_run(o), [("boringssl", "SLH-DSA-SHA2-128f", "*")])


class Verdict(unittest.TestCase):
    def test_order_statistics(self):
        # [x(k), x(n+1-k)] at 95%: n = 6 -> k = 1, n = 9 -> 2, n = 15 -> 4.
        self.assertEqual([stats.sign_test_k(n) for n in (5, 6, 9, 15)], [0, 1, 2, 4])
        self.assertEqual(stats.MIN_ROUNDS, min(n for n in range(1, 50) if stats.sign_test_k(n)))
        low, high, coverage = stats.median_interval(list(range(9)))
        self.assertEqual((low, high), (1, 7))
        self.assertAlmostEqual(coverage, 1 - 20 / 512)

    def test_resolved_and_not(self):
        o = []
        for r in range(stats.MIN_ROUNDS):
            o.append(obs("nirapod", r, [80 + r]))
            o.append(obs("base", r, [100]))
        self.assertEqual(ratios(o)[0]["verdict"], "R < 1")
        self.assertEqual(ratios(o[:-2])[0]["verdict"], "inconclusive")   # 5 rounds
        o += [obs("nirapod", r, [101]) for r in range(6, 9)]
        o += [obs("base", r, [100]) for r in range(6, 9)]
        self.assertEqual(ratios(o)[0]["verdict"], "inconclusive")    # x(8) > 1

    def simulate(self, rounds, factor, trials, rng):
        resolved = 0
        for _ in range(trials):
            o = [obs(name, r, [scale * rng.lognormvariate(0, 0.03)])
                 for r in range(rounds) for name, scale in (("nirapod", factor), ("base", 1.0))]
            resolved += ratios(o)[0]["verdict"] != "inconclusive"
        return resolved / trials

    def test_equal_speeds_rarely_resolve(self):
        # Two implementations of equal speed, 3% lognormal noise per round:
        # the comparison may resolve in no more than 5% of runs (expected
        # 3.1%, 3.9% and 3.5%; the quartile rule this replaced gave 18% at 9).
        rng = random.Random(205)
        for rounds in (6, 9, 15):
            self.assertLessEqual(self.simulate(rounds, 1.0, 3000, rng), 0.05, rounds)

    def test_real_difference_resolves(self):
        rng = random.Random(180)
        self.assertGreaterEqual(self.simulate(9, 0.9, 500, rng), 0.95)


class Paired(unittest.TestCase):
    def test_throughput(self):
        tp = []
        for r in range(6):
            tp.append(dict(name="nirapod", set="S", op="sign", threads=4, round=r, status="ok",
                           calls=200, wall_ns=1e9))
            tp.append(dict(name="base", set="S", op="sign", threads=4, round=r, status="ok",
                           calls=100, wall_ns=1e9))
        (row,) = stats.throughput_ratios(tp, "nirapod")
        self.assertAlmostEqual(row["R"], 0.5)
        self.assertEqual((row["threads"], row["verdict"]), (4, "R < 1"))
        rates = {r["name"]: r["median_ops_per_s"] for r in stats.throughput_rows(tp)}
        self.assertEqual(rates, dict(nirapod=200.0, base=100.0))

    def test_fault_check_cost(self):
        o = []
        for r in range(6):
            o.append(obs("nirapod-testing", r, [150], op="sign"))
            o.append(obs("nirapod-testing", r, [100], op="sign-unchecked"))
        (row,) = stats.fault_check_cost(o, "nirapod-testing")
        self.assertAlmostEqual(row["R"], 1.5)
        self.assertEqual(row["verdict"], "R > 1")

    def test_summarise(self):
        (row,) = stats.summarise([obs("a", 0, [1, 2, 3]), obs("a", 1, [5, 6, 7])])
        self.assertEqual((row["median_ns"], row["rounds"], row["samples"]), (4, 2, 6))
        self.assertEqual(row["round_median_ns"], [2, 6])


# /proc/cpuinfo of an arm64 Linux machine with two cores (the format of
# arch/arm64/kernel/cpuinfo.c), and of one with two core types.
CPUINFO_N1 = """processor\t: 0
BogoMIPS\t: 50.00
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer\t: 0x41
CPU architecture: 8
CPU variant\t: 0x3
CPU part\t: 0xd0c
CPU revision\t: 1

processor\t: 1
BogoMIPS\t: 50.00
CPU implementer\t: 0x41
CPU architecture: 8
CPU variant\t: 0x3
CPU part\t: 0xd0c
CPU revision\t: 1
"""

CPUINFO_MIXED = """processor\t: 0
CPU implementer\t: 0x41
CPU variant\t: 0x0
CPU part\t: 0xd80
CPU revision\t: 1

processor\t: 1
CPU implementer\t: 0x41
CPU variant\t: 0x0
CPU part\t: 0xd81
CPU revision\t: 1

processor\t: 2
CPU implementer\t: 0x41
CPU variant\t: 0x0
CPU part\t: 0xd81
CPU revision\t: 1
"""


class Cpu(unittest.TestCase):
    def test_known_core(self):
        name, ids = host.aarch64_cpu(CPUINFO_N1, "0x00000000413fd0c1")
        self.assertEqual(name, "Arm Neoverse N1")
        self.assertEqual(ids[0]["count"], 2)
        self.assertEqual(ids[0]["midr_el1_cpu0"], "0x00000000413fd0c1")

    def test_unknown_core_prints_codes(self):
        info = CPUINFO_N1.replace("0x41", "0x61").replace("0xd0c", "0x048")
        name, _ = host.aarch64_cpu(info)
        self.assertEqual(name, "implementer 0x61 (Apple), part 0x048")
        name, _ = host.aarch64_cpu(info.replace("0x61", "0x99"))
        self.assertEqual(name, "implementer 0x99, part 0x048")

    def test_two_core_types(self):
        name, ids = host.aarch64_cpu(CPUINFO_MIXED)
        self.assertEqual(name, "Arm Cortex-A520 x1 + Arm Cortex-A720 x2")
        self.assertEqual(len(ids), 2)

    def test_midr_register_alone(self):
        name, ids = host.aarch64_cpu("processor\t: 0\nBogoMIPS\t: 48.00\n", "0x00000000410fd4f0")
        self.assertEqual(name, "Arm Neoverse V2")
        self.assertEqual((ids[0]["variant"], ids[0]["revision"]), ("0x0", 0))

    def test_nothing_readable_is_said(self):
        name, _ = host.aarch64_cpu("processor\t: 0\n")
        self.assertNotIn("unknown", name)

    def test_low_power_mode(self):
        self.assertTrue(host.low_power_mode(" lowpowermode         1\n"))
        self.assertFalse(host.low_power_mode(" lowpowermode         0\n"))


@unittest.skipUnless(shutil.which("git"), "git not installed")
class Tree(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.git("init", "-q")
        self.write(".gitignore", "/build/\n")
        self.write("a.mk", "A := 1\n")
        self.git("add", ".")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-q", "-m", "t")

    def tearDown(self):
        shutil.rmtree(self.root)

    def git(self, *args):
        subprocess.run(["git", "-C", self.root, *args], check=True, capture_output=True)

    def write(self, path, text):
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(text)

    def test_clean_and_ignored(self):
        self.write("build/out.o", "x")
        t = revision.tree_state(self.root)
        self.assertTrue(t["matches_commit"])
        self.assertEqual(t["tree_sha256"], t["commit_tree_sha256"])
        self.assertEqual(t["changes"], [])

    def test_untracked_and_modified(self):
        self.write("b/extra.mk", "B := 2\n")
        t = revision.tree_state(self.root)
        self.assertFalse(t["matches_commit"])
        self.assertEqual([(c["path"], c["state"]) for c in t["changes"]],
                         [("b/extra.mk", "untracked")])
        os.remove(os.path.join(self.root, "b", "extra.mk"))
        self.write("a.mk", "A := 3\n")
        t = revision.tree_state(self.root)
        self.assertEqual([(c["path"], c["state"]) for c in t["changes"]], [("a.mk", "modified")])
        os.remove(os.path.join(self.root, "a.mk"))
        t = revision.tree_state(self.root)
        self.assertEqual([(c["path"], c["state"]) for c in t["changes"]], [("a.mk", "deleted")])


def record(kind="measurement", cpu="Test CPU", reasons=()):
    o = [obs("nirapod", 0, [80, 82]), obs("base", 0, [100, 101])]
    prog = dict(sets=["SLH-DSA-SHA2-128f"], program_sha256="ab" * 32, harness_cc="cc 1",
                harness_cflags="-O2")
    return dict(schema="nirapod-slhdsa-bench/1", kind=kind, trial_reasons=list(reasons),
                config=dict(rounds=1, samples=2, warmup=1, mlen=32, cpu=None),
                environment=dict(cpu=cpu, os="Test OS", kernel="1", virtualisation="none",
                                 frequency="fixed", placement="pinned", niceness=0),
                timer=dict(timer="test", overhead_ns=0),
                implementations=dict(
                    nirapod=dict(revision=dict(commit="0" * 40, matches_commit=True,
                                               tree_sha256="1" * 64, changes=[]),
                                 target="t", library_sha256="2" * 64, library_cc="cc 1",
                                 library_cflags="-O2", jasmin_commit="3" * 40,
                                 jasmin_series_sha256="4" * 64, jasminc_sha256="5" * 64,
                                 programs=[prog]),
                    base=dict(programs=[dict(prog, pin=dict(kind="git", identity="6" * 40),
                                             build="opts=--fast")])),
                summary=stats.summarise(o), ratios=ratios(o), not_run=[], stack=[],
                code_size=dict(library="lib.a", total=dict(code=1, rodata=2, data=3, bss=4)),
                notes=dict(base="test"))


class Render(unittest.TestCase):
    def test_table_row(self):
        text = render.render(record())
        self.assertIn("| SLH-DSA-SHA2-128f sign (hedged) | 81 ns | base (strongest) | 100 ns | "
                      "0.806 (inconclusive) | no 95% CI (too few rounds); range 0.806-0.806 "
                      "over 1 rounds;", text)
        self.assertIn("Throughput: not measured in this run", text)
        self.assertNotIn("Smoke run", text)
        self.assertNotIn("Trial run", text)

    def test_builds_are_identified(self):
        text = render.render(record())
        self.assertIn("| base | SLH-DSA-SHA2-128f | git " + "6" * 40 + " | opts=--fast | cc 1 | "
                      "harness -O2 | " + "ab" * 32 + " |", text)
        self.assertIn("| jasminc SHA-256 | " + "5" * 64 + " |", text)

    def test_smoke_and_trial_are_labelled(self):
        self.assertTrue(render.render(record(kind="smoke")).startswith("**Smoke run"))
        text = render.render(record(kind="trial", reasons=["run at nice 15"]))
        self.assertTrue(text.startswith("**Trial run, not a measurement: run at nice 15."))

    def test_path_is_refused(self):
        with self.assertRaises(render.Failure):
            render.render(record(cpu="cpu at /home/someone/x"))


class Scrub(unittest.TestCase):
    def test_paths_are_replaced(self):
        text = f"cc -I{run.ROOT}/include -L/opt/b/out"
        self.assertEqual(run.scrub(text, "/opt/b"), "cc -I<root>/include -L<baselines>/out")


def ar(name, obj):
    """A BSD ar archive with one member (the name precedes the data)."""
    body = name.encode().ljust(8, b"\0") + obj
    head = f"#1/8".ljust(16) + "0".ljust(32) + str(len(body)).ljust(10) + "`\n"
    return b"!<arch>\n" + head.encode() + body


class CodeSize(unittest.TestCase):
    def size(self, blob):
        with tempfile.NamedTemporaryFile(suffix=".a", delete=False) as f:
            f.write(blob)
        try:
            return codesize.library_size(f.name)["total"]
        finally:
            os.remove(f.name)

    def test_elf_classes(self):
        # A minimal ELF64 object: null, .text (AX), .rodata (A), .data (WA),
        # .bss (WA, NOBITS), .symtab (not allocated).
        sections = [(0, 0, 0), (1, 0x6, 10), (1, 0x2, 20), (1, 0x3, 30), (8, 0x3, 40),
                    (2, 0x0, 50)]
        head = bytearray(64)
        head[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", head, 0x28, 64)
        struct.pack_into("<HH", head, 0x3A, 64, len(sections))
        table = b"".join(struct.pack("<IIQQQQIIQQ", 0, t, f, 0, 0, size, 0, 0, 1, 0)
                         for t, f, size in sections)
        obj = bytes(head) + table
        member = b"a.o/".ljust(16) + b"0".ljust(32) + str(len(obj)).encode().ljust(10) + b"`\n"
        self.assertEqual(self.size(b"!<arch>\n" + member + obj),
                         dict(code=10, rodata=20, data=30, bss=40))

    def test_macho_classes(self):
        # One LC_SEGMENT_64 with __TEXT,__text (pure instructions),
        # __TEXT,__const, __DATA,__data, __DATA,__bss (zero-fill) and
        # __LD,__compact_unwind (not mapped).
        sections = [("__text", "__TEXT", 10, 0x80000400), ("__const", "__TEXT", 20, 0),
                    ("__data", "__DATA", 30, 0), ("__bss", "__DATA", 40, 0x1),
                    ("__compact_unwind", "__LD", 50, 0x02000000)]
        sects = b"".join(struct.pack("<16s16sQQIIIIIIII", n.encode(), s.encode(), 0, size,
                                     0, 0, 0, 0, flags, 0, 0, 0)
                         for n, s, size, flags in sections)
        seg = struct.pack("<II16sQQQQiiII", 0x19, 72 + len(sects), b"", 0, 0, 0, 0, 7, 7,
                          len(sections), 0) + sects
        obj = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 1, 1, len(seg), 0, 0) + seg
        self.assertEqual(self.size(ar("a.o", obj)), dict(code=10, rodata=20, data=30, bss=40))


if __name__ == "__main__":
    unittest.main()
