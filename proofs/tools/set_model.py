# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# proofs/tools/set_model.py
# =========================
#
# Usage: python3 -I tools/set_model.py --set SET --params FILE --constants FILE
#                                      --thash FILE --model CoreExtracted.ec
#                                      -o SetModel.ec
#
# Writes SetModel.ec, the theory through which the per-set correctness
# proofs (correctness/core/) name what differs between parameter sets.
# jasmin2ec substitutes every `param int` by its value and names each array
# theory after its size in bytes, so the same Jasmin procedure has, for two
# sets, different loop bounds and argument types (`BArray34.t` for the
# digest of SLH-DSA-SHAKE-128f, `BArray30.t` for SHA2-128s). The proofs are
# written once against fixed names instead:
#
#   P              the FIPS 205 parameter record of the set
#                  (spec/slhdsa/FIPS205_Params.ec)
#   <param>_val    P.`<param> as a literal, for each base parameter; proved
#                  by evaluation, so a Jasmin parameter file that disagrees
#                  with FIPS 205 Table 2 fails to check
#   <Role>         an alias of the array theory of one buffer kind
#                  (ROLES), for example Digest = BArray34, or of the
#                  theory of its fixed-size slots, for example
#                  TLenNode = SBArray560_16
#
# Every role must be an array theory the model itself requires, or the
# script fails: a role then always names the type of the model's own
# procedures. The values come from the Jasmin parameter file, the derived
# constants of constants.jinc and the context size of the set's tweakable
# hash file (--thash, the thash_*.jinc the set's compilation unit
# requires), evaluated here; nothing is computed from the set's name.

import argparse
import ast
import os
import re
import sys

# The base parameters of FIPS 205 Table 2, as the Jasmin parameter file
# names them, with the field of the specification's record.
BASE = [("SLH_N", "n"), ("SLH_H", "h"), ("SLH_D", "d"), ("SLH_HP", "hp"),
        ("SLH_A", "a"), ("SLH_K", "k"), ("SLH_LGW", "lgw"), ("SLH_M", "m")]

# The treehash fold keeps one node per height of the tallest tree it
# builds, max(a, hp) + 1 = a + 1 nodes, since a > hp in every set
# (treehash.jinc, SLH_FOLD_SLOTS); FORS and XMSS trees share the buffer.
FOLD_BUF = "(SLH_A + 1) * SLH_N"

# Buffer kinds and their size in bytes, as expressions over the Jasmin
# parameters: one size names the array theory BArray<size>, two sizes the
# theory SBArray<size>_<slot> of the array's slots of slot bytes. A kind
# used by no procedure of the set's model is an error. A kind listed in
# THASH_ROLES exists only in the sets whose tweakable hash file is the one
# named there.
ROLES = [
    ("Node", ("SLH_N",), "an n-byte value (u8[n])"),
    ("Node2", ("2 * SLH_N",), "two n-byte values (u8[2n])"),
    ("Digest", ("SLH_M",), "the message digest (u8[m])"),
    ("ForsIdx", ("4 * SLH_K",), "the k FORS indices (u32[k])"),
    ("WotsDigits", ("SLH_LEN",), "the len WOTS+ digits (u8[len])"),
    ("Ctx", ("8 * THASH_CTX_WORDS",),
     "the tweakable hash context (u64[THASH_CTX_WORDS])"),
    ("TLenIn", ("SLH_LEN * SLH_N",),
     "len n-byte values, the input of T_len (u8[len n])"),
    ("TLenNode", ("SLH_LEN * SLH_N", "SLH_N"), "the n-byte slots of a TLenIn"),
    ("TKIn", ("SLH_K * SLH_N",), "k n-byte values, the input of T_k (u8[k n])"),
    ("Node4", ("4 * SLH_N",), "four n-byte values, one per lane (u8[4n])"),
    ("TLenIn4", ("4 * SLH_LEN * SLH_N",),
     "four TLenIn, one per lane (u8[4 len n])"),
    ("Node2Half", ("2 * SLH_N", "SLH_N"), "the two n-byte halves of a Node2"),
    ("Node4Node", ("4 * SLH_N", "SLH_N"), "the n-byte lanes of a Node4"),
    ("TKNode", ("SLH_K * SLH_N", "SLH_N"), "the n-byte slots of a TKIn"),
    ("FoldBuf", (FOLD_BUF,),
     "the treehash fold stack: one node per height (u8[(a + 1) n])"),
    ("FoldNode", (FOLD_BUF, "SLH_N"), "the n-byte slots of a FoldBuf"),
    ("XmssSig", ("SLH_XMSS_SIG_BYTES",),
     "an XMSS signature: WOTS+ signature, then hp nodes (u8[(len + hp) n])"),
    ("XmssSigNode", ("SLH_XMSS_SIG_BYTES", "SLH_N"),
     "the n-byte slots of an XmssSig"),
    ("XmssSigWots", ("SLH_XMSS_SIG_BYTES", "SLH_WOTS_SIG_BYTES"),
     "the WOTS+ signature slot of an XmssSig (u8[len n])"),
    ("ForsSig", ("SLH_FORS_SIG_BYTES",),
     "a FORS signature: k trees of a secret and a nodes (u8[k (a + 1) n])"),
    ("ForsSigNode", ("SLH_FORS_SIG_BYTES", "SLH_N"),
     "the n-byte slots of a ForsSig"),
]

# The SHA2 T_l and T_k hash their input in a work buffer of whole SHA-512
# blocks (thash_sha2_t.jinc: 22 bytes of compressed address, the l n-byte
# values, then at least 17 bytes of padding), read in 64-byte SHA-256 or
# 128-byte SHA-512 blocks.
TLEN_BUF = "128 * ((22 + SLH_LEN * SLH_N + 144) / 128)"
TK_BUF = "128 * ((22 + SLH_K * SLH_N + 144) / 128)"
THASH_ROLES = {
    "thash_sha2.jinc": [
        ("TLenBuf", (TLEN_BUF,), "the T_len work buffer"),
        ("TLenBlk256", (TLEN_BUF, "64"), "its 64-byte SHA-256 blocks"),
        ("TLenBlk512", (TLEN_BUF, "128"), "its 128-byte SHA-512 blocks"),
        ("TKBuf", (TK_BUF,), "the T_k work buffer"),
        ("TKBlk256", (TK_BUF, "64"), "its 64-byte SHA-256 blocks"),
        ("TKBlk512", (TK_BUF, "128"), "its 128-byte SHA-512 blocks"),
    ],
}

# The tweakable hash file defines its context size; only that parameter
# is read from it.
CTX_WORDS = re.compile(r"^param\s+int\s+THASH_CTX_WORDS\s*=\s*([^;]+);", re.M)

PARAM = re.compile(r"^\s*param\s+int\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);", re.M)


def evaluate(expr, env):
    """Value of a Jasmin integer expression over earlier parameters."""
    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.Name) and n.id in env:
            return env[n.id]
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            ops = {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
                   ast.Div: lambda: a // b, ast.Mod: lambda: a % b, ast.LShift: lambda: a << b}
            if type(n.op) in ops and (not isinstance(n.op, (ast.Div, ast.Mod)) or b > 0):
                return ops[type(n.op)]()
        raise ValueError(f"unsupported parameter expression '{expr}'")
    return ev(ast.parse(expr.strip(), mode="eval").body)


def parameters(*paths):
    env = {}
    for path in paths:
        with open(path, encoding="utf-8") as f:
            text = re.sub(r"/\*.*?\*/", "", f.read(), flags=re.S)
        for name, expr in PARAM.findall(text):
            if name in env:
                raise ValueError(f"{path}: {name} defined twice")
            env[name] = evaluate(expr, env)
    return env


def ctx_words(path, env):
    """THASH_CTX_WORDS of a tweakable hash file, over the set's parameters."""
    with open(path, encoding="utf-8") as f:
        text = re.sub(r"/\*.*?\*/", "", f.read(), flags=re.S)
    found = CTX_WORDS.findall(text)
    if len(found) != 1:
        raise ValueError(f"{path}: THASH_CTX_WORDS must be defined exactly once")
    return evaluate(found[0], env)


def theory_key(name):
    """Sort key of an array theory name: BArray before SBArray, by size."""
    return (name.startswith("S"), [int(x) for x in re.findall(r"[0-9]+", name)])


def model_arrays(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    names = set()
    for group in re.findall(r"^require import\s+([^.]*)\.", text, re.M):
        names |= set(group.split())
    arrays = {n for n in names if re.fullmatch(r"S?BArray[0-9_]+", n)}
    if not arrays:
        raise ValueError(f"{path}: no array theories required")
    return arrays


def render(pset, env, arrays, thash):
    family, strength = pset.split("_")
    lines = [
        f"(* The names the per-set proofs use for SLH-DSA-{family.upper()}-{strength}. *)",
        "",
        "require import AllCore.",
        "require FIPS205_Params.",
    ]
    roles = []
    for role, exprs, what in ROLES + THASH_ROLES.get(thash, []):
        sizes = [evaluate(e, env) for e in exprs]
        theory = ("S" if len(sizes) == 2 else "") + "BArray" + "_".join(map(str, sizes))
        if theory not in arrays:
            raise ValueError(f"role {role} ({what}) is {theory}, which the model does not require")
        roles.append((role, theory, what))
    lines.append("require " + " ".join(sorted({t for _, t, _ in roles}, key=theory_key)) + ".")
    lines += ["", f"op P : FIPS205_Params.params = FIPS205_Params.slh_dsa_{pset}.", ""]
    for jname, field in BASE:
        if jname not in env:
            raise ValueError(f"parameter {jname} is missing")
        lines.append(f"lemma {field}_val : P.`{field} = {env[jname]} by rewrite /P.")
    lines.append("")
    for role, theory, what in roles:
        # jasmin2ec puts the operators of a slot theory in an inner clone
        # of the same name; the role names that clone.
        target = f"{theory}.{theory}" if theory.startswith("S") else theory
        lines.append(f"(* {what} *)")
        lines.append(f"theory {role} = {target}.")
    return "\n".join(lines) + "\n"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True)
    ap.add_argument("--params", required=True)
    ap.add_argument("--constants", required=True)
    ap.add_argument("--thash", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("-o", dest="out", required=True)
    args = ap.parse_args(argv[1:])
    if not re.fullmatch(r"(sha2|shake)_(128|192|256)[sf]", args.set):
        print(f"set_model.py: '{args.set}' is not a parameter set name", file=sys.stderr)
        return 1
    try:
        env = parameters(args.params, args.constants)
        env["THASH_CTX_WORDS"] = ctx_words(args.thash, env)
        text = render(args.set, env, model_arrays(args.model), os.path.basename(args.thash))
    except (OSError, ValueError) as e:
        print(f"set_model.py: {e}", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
