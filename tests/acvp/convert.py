# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# convert.py
# ==========
#
# Joins the NIST ACVP SLH-DSA prompt and expectedResults files into one flat
# text file per mode (keyGen, sigGen, sigVer) that the C runner reads without
# a JSON parser. One test case per line, space-separated key=value fields,
# values in upper-case hex where they are byte strings:
#
#   keyGen tg=1 tc=1 set=SLH-DSA-SHA2-128s skSeed=.. skPrf=.. pkSeed=.. pk=.. sk=..
#   sigGen tg=.. tc=.. set=.. iface=internal|external ph=none|<hashAlg>
#          det=1|0 sk=.. msg=.. [ctx=..] [addrnd=..] sig=..
#   sigVer tg=.. tc=.. set=.. iface=.. ph=.. pk=.. msg=.. [ctx=..] sig=.. pass=1|0
#
# An empty byte string is written as "key=" with no digits. ph is "-" on the
# internal interface, where no message framing exists.
#
# The conversion is strict: an unknown mode, field, parameter set, interface
# or hash name, a malformed hex string, a prompt case without its expected
# result, or the reverse, aborts with a non-zero exit. Nothing is skipped
# silently, so every case NIST published reaches the runner. Output files
# are written under a temporary name and renamed only when complete.
#
# This script does not check where its input came from; run it on the
# directory tests/vectors/fetch-acvp.py has verified against the lock.
# Run it with "python3 -I" so nothing beside the input can be imported.
#
# Usage: convert.py <json-files dir> <output dir>

import json
import os
import re
import sys

SETS = {
    f"SLH-DSA-{h}-{l}{v}"
    for h in ("SHA2", "SHAKE")
    for l in ("128", "192", "256")
    for v in ("s", "f")
}
HASHES = {
    "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224",
    "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
    "SHAKE-128", "SHAKE-256",
}
HEX = re.compile(r"\A(?:[0-9A-F]{2})*\Z")


class ConvertError(Exception):
    pass


def hexfield(value, what):
    if not isinstance(value, str) or not HEX.match(value.upper()):
        raise ConvertError(f"{what}: not a hex byte string")
    return value.upper()


def no_duplicates(pairs):
    """json.load keeps the last of two equal keys silently; refuse instead."""
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ConvertError(f"duplicate JSON key {k!r}")
        obj[k] = v
    return obj


def load(path):
    with open(path, "rb") as f:
        return json.load(f, object_pairs_hook=no_duplicates)


def index_results(results, mode):
    if results.get("algorithm") != "SLH-DSA" or results.get("mode") != mode:
        raise ConvertError(f"{mode}: expectedResults header mismatch")
    out = {}
    for g in results["testGroups"]:
        for t in g["tests"]:
            key = (g["tgId"], t["tcId"])
            if key in out:
                raise ConvertError(f"{mode}: duplicate result {key}")
            out[key] = t
    return out


def check_keys(obj, allowed, what):
    extra = set(obj) - set(allowed)
    if extra:
        raise ConvertError(f"{what}: unexpected fields {sorted(extra)}")


def convert_mode(src, mode):
    base = os.path.join(src, f"SLH-DSA-{mode}-FIPS205")
    prompt = load(os.path.join(base, "prompt.json"))
    results = index_results(load(os.path.join(base, "expectedResults.json")), mode)
    if (prompt.get("algorithm") != "SLH-DSA" or prompt.get("mode") != mode
            or prompt.get("revision") != "FIPS205"):
        raise ConvertError(f"{mode}: prompt header mismatch")

    lines = []
    seen = set()
    for g in prompt["testGroups"]:
        tg = g["tgId"]
        what = f"{mode} tg={tg}"
        if g.get("testType") != "AFT":
            raise ConvertError(f"{what}: unsupported testType {g.get('testType')}")
        pset = g.get("parameterSet")
        if pset not in SETS:
            raise ConvertError(f"{what}: unknown parameter set {pset}")

        if mode == "keyGen":
            check_keys(g, ("tgId", "testType", "parameterSet", "tests"), what)
        else:
            iface = g.get("signatureInterface")
            if iface not in ("internal", "external"):
                raise ConvertError(f"{what}: unknown interface {iface}")
            allowed = ["tgId", "testType", "parameterSet", "signatureInterface", "tests"]
            if iface == "external":
                allowed.append("preHash")
                if g.get("preHash") not in ("pure", "preHash"):
                    raise ConvertError(f"{what}: unknown preHash {g.get('preHash')}")
            if mode == "sigGen":
                allowed.append("deterministic")
                if not isinstance(g.get("deterministic"), bool):
                    raise ConvertError(f"{what}: deterministic flag missing")
            check_keys(g, allowed, what)

        for t in g["tests"]:
            tc = t["tcId"]
            what = f"{mode} tg={tg} tc={tc}"
            key = (tg, tc)
            if key not in results:
                raise ConvertError(f"{what}: no expected result")
            seen.add(key)
            exp = results[key]
            f = [mode, f"tg={tg}", f"tc={tc}", f"set={pset}"]

            if mode == "keyGen":
                check_keys(t, ("tcId", "skSeed", "skPrf", "pkSeed"), what)
                check_keys(exp, ("tcId", "pk", "sk"), what)
                for k in ("skSeed", "skPrf", "pkSeed"):
                    f.append(f"{k}={hexfield(t[k], what)}")
                f.append(f"pk={hexfield(exp['pk'], what)}")
                f.append(f"sk={hexfield(exp['sk'], what)}")
                lines.append(" ".join(f))
                continue

            iface = g["signatureInterface"]
            f.append(f"iface={iface}")
            allowed = ["tcId", "message"]
            if iface == "internal":
                f.append("ph=-")
            elif g["preHash"] == "pure":
                f.append("ph=none")
                allowed.append("context")
            else:
                if t.get("hashAlg") not in HASHES:
                    raise ConvertError(f"{what}: unknown hashAlg {t.get('hashAlg')}")
                f.append(f"ph={t['hashAlg']}")
                allowed += ["context", "hashAlg"]

            if mode == "sigGen":
                det = g["deterministic"]
                allowed.append("sk")
                if not det:
                    allowed.append("additionalRandomness")
                check_keys(t, allowed, what)
                check_keys(exp, ("tcId", "signature"), what)
                f.append(f"det={int(det)}")
                f.append(f"sk={hexfield(t['sk'], what)}")
            else:
                allowed += ["pk", "signature"]
                check_keys(t, allowed, what)
                check_keys(exp, ("tcId", "testPassed"), what)
                if not isinstance(exp.get("testPassed"), bool):
                    raise ConvertError(f"{what}: testPassed missing")
                f.append(f"pk={hexfield(t['pk'], what)}")

            f.append(f"msg={hexfield(t['message'], what)}")
            if "context" in allowed:
                f.append(f"ctx={hexfield(t['context'], what)}")
            if mode == "sigGen":
                if not g["deterministic"]:
                    f.append(f"addrnd={hexfield(t['additionalRandomness'], what)}")
                f.append(f"sig={hexfield(exp['signature'], what)}")
            else:
                f.append(f"sig={hexfield(t['signature'], what)}")
                f.append(f"pass={int(exp['testPassed'])}")
            lines.append(" ".join(f))

    missing = set(results) - seen
    if missing:
        raise ConvertError(f"{mode}: expected results without a prompt: {sorted(missing)[:5]}")
    return lines


def main(argv):
    if len(argv) != 3:
        print("usage: convert.py <json-files dir> <output dir>", file=sys.stderr)
        return 2
    src, dst = argv[1], argv[2]
    os.makedirs(dst, exist_ok=True)
    for mode in ("keyGen", "sigGen", "sigVer"):
        try:
            lines = convert_mode(src, mode)
        except (ConvertError, KeyError, OSError, ValueError) as e:
            print(f"convert: {mode}: {e}", file=sys.stderr)
            return 1
        tmp = os.path.join(dst, f".{mode}.txt.tmp")
        with open(tmp, "w") as out:
            out.write("".join(line + "\n" for line in lines))
        os.replace(tmp, os.path.join(dst, f"{mode}.txt"))
        print(f"convert: {mode}: {len(lines)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
