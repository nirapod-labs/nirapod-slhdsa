# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# proofs/tools/set_model.py
# =========================
#
# Usage: python3 -I tools/set_model.py --set SET --params FILE --constants FILE
#                                      --model CoreExtracted.ec -o SetModel.ec
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
#                  (ROLES), for example Digest = BArray34
#
# Every role must be an array theory the model itself requires, or the
# script fails: a role then always names the type of the model's own
# procedures. The values come from the Jasmin parameter file and the
# derived constants of constants.jinc, evaluated here; nothing is computed
# from the set's name.

import argparse
import ast
import re
import sys

# The base parameters of FIPS 205 Table 2, as the Jasmin parameter file
# names them, with the field of the specification's record.
BASE = [("SLH_N", "n"), ("SLH_H", "h"), ("SLH_D", "d"), ("SLH_HP", "hp"),
        ("SLH_A", "a"), ("SLH_K", "k"), ("SLH_LGW", "lgw"), ("SLH_M", "m")]

# Buffer kinds and their size in bytes, as an expression over the Jasmin
# parameters. A kind used by no procedure of the set's model is an error.
ROLES = [
    ("Node", "SLH_N", "an n-byte value (u8[n])"),
    ("Node2", "2 * SLH_N", "two n-byte values (u8[2n])"),
    ("Digest", "SLH_M", "the message digest (u8[m])"),
    ("ForsIdx", "4 * SLH_K", "the k FORS indices (u32[k])"),
    ("WotsDigits", "SLH_LEN", "the len WOTS+ digits (u8[len])"),
]

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


def render(pset, env, arrays):
    family, strength = pset.split("_")
    lines = [
        f"(* The names the per-set proofs use for SLH-DSA-{family.upper()}-{strength}. *)",
        "",
        "require import AllCore.",
        "require FIPS205_Params.",
    ]
    roles = []
    for role, expr, what in ROLES:
        size = evaluate(expr, env)
        theory = f"BArray{size}"
        if theory not in arrays:
            raise ValueError(f"role {role} ({what}) is {theory}, which the model does not require")
        roles.append((role, theory, what))
    lines.append("require " + " ".join(sorted({t for _, t, _ in roles},
                                              key=lambda t: int(t[6:]))) + ".")
    lines += ["", f"op P : FIPS205_Params.params = FIPS205_Params.slh_dsa_{pset}.", ""]
    for jname, field in BASE:
        if jname not in env:
            raise ValueError(f"parameter {jname} is missing")
        lines.append(f"lemma {field}_val : P.`{field} = {env[jname]} by rewrite /P.")
    lines.append("")
    for role, theory, what in roles:
        lines.append(f"(* {what} *)")
        lines.append(f"theory {role} = {theory}.")
    return "\n".join(lines) + "\n"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True)
    ap.add_argument("--params", required=True)
    ap.add_argument("--constants", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("-o", dest="out", required=True)
    args = ap.parse_args(argv[1:])
    if not re.fullmatch(r"(sha2|shake)_(128|192|256)[sf]", args.set):
        print(f"set_model.py: '{args.set}' is not a parameter set name", file=sys.stderr)
        return 1
    try:
        text = render(args.set, parameters(args.params, args.constants), model_arrays(args.model))
    except (OSError, ValueError) as e:
        print(f"set_model.py: {e}", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
