# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/core/acvp-subset.py
# =========================
#
# Writes tests/core/acvp-subset.txt, the known answers that `make check`
# runs, from the NIST ACVP SLH-DSA vector files:
#
#     python3 tests/core/acvp-subset.py <json-files> > tests/core/acvp-subset.txt
#
# <json-files> is the gen-val/json-files directory of ACVP-Server
# (https://github.com/usnistgov/ACVP-Server) at the commit pinned below,
# or any directory holding the same SLH-DSA-<mode>-FIPS205/ files. Each of
# the six files read is checked against its SHA-256 first; a mismatch stops
# the script before anything is written.
#
# Selection, per parameter set, so that every set has one case of each
# kind through the external interface (FIPS 205 section 10):
#
#     keygen   keyGen, the test with the lowest tcId
#     siggen   sigGen, external interface, deterministic, pure: the test
#              with the shortest message (lowest tcId among equals)
#     siggen   the same, pre-hash, with the i-th pre-hash function of
#              HASH_ALGS for the i-th set: the twelve sets cover the twelve
#              functions of FIPS 205 section 10.2 once each
#     sigver   sigVer, external interface: the shortest-message test that
#              must fail and whose signature has the set's length, so that
#              it is judged by the full algorithm, not by its length
#
# and, for SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s, one case of each hash
# family that fixes opt_rand:
#
#     hsiggen  sigGen, external interface, hedged, pure: the shortest
#              message; additionalRandomness is opt_rand
#     isiggen  sigGen, internal interface (FIPS 205 Algorithm 19), hedged:
#              the shortest message
#
# Output: one case per line, fields separated by one space, byte strings in
# upper-case hex and "-" for an empty one:
#
#     keygen  <set> <tcId> <SK.seed> <SK.prf> <PK.seed> <pk> <sk>
#     siggen  <set> <tcId> <pure|hashAlg> <sk> <message> <context> <signature>
#     hsiggen <set> <tcId> <pure> <sk> <message> <context> <opt_rand> <signature>
#     isiggen <set> <tcId> <sk> <message> <opt_rand> <signature>
#     sigver  <set> <tcId> <pure|hashAlg> <0|1> <pk> <message> <context> <signature>
#
# The order follows FIPS 205 Table 2. The script reads only the files named
# below and uses only the Python standard library.

import hashlib
import json
import os
import sys

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
ACVP_TAG = "v1.1.0.43"

PINS = {
    "SLH-DSA-keyGen-FIPS205/prompt.json":
        "bce170976f257ee3dfc8c54ea46722ccb553539847daa6d8048f0216cc28b51c",
    "SLH-DSA-keyGen-FIPS205/expectedResults.json":
        "f35f74b6676d6b369c87e88c36698f28c14d5929d31e507d910288c69258afee",
    "SLH-DSA-sigGen-FIPS205/prompt.json":
        "afa673eacdf0aec53512a159159b7632684adfcd0d88f8640a7f6f5796aacdc8",
    "SLH-DSA-sigGen-FIPS205/expectedResults.json":
        "71e8e0f7e4b0cfd1747314299204d9d4d50968d200a4ae873921eaa7aabeaad1",
    "SLH-DSA-sigVer-FIPS205/prompt.json":
        "4e7beb1233e47baa0acdd36417c66c45811aa40a4e32ffdb1a35d93b13b289fb",
    "SLH-DSA-sigVer-FIPS205/expectedResults.json":
        "259f5e2a0665de0adc0fefa45b5db3a2a6ed13c3c44d14bdaf64a80aee12c687",
}

# FIPS 205 Table 2 order, with the signature size of each set.
SETS = [
    ("SLH-DSA-SHA2-128s", 7856), ("SLH-DSA-SHAKE-128s", 7856),
    ("SLH-DSA-SHA2-128f", 17088), ("SLH-DSA-SHAKE-128f", 17088),
    ("SLH-DSA-SHA2-192s", 16224), ("SLH-DSA-SHAKE-192s", 16224),
    ("SLH-DSA-SHA2-192f", 35664), ("SLH-DSA-SHAKE-192f", 35664),
    ("SLH-DSA-SHA2-256s", 29792), ("SLH-DSA-SHAKE-256s", 29792),
    ("SLH-DSA-SHA2-256f", 49856), ("SLH-DSA-SHAKE-256f", 49856),
]

# The pre-hash functions of FIPS 205 section 10.2 by their ACVP names, in
# the order of nirapod_slhdsa_prehash.
HASH_ALGS = [
    "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA2-512/224", "SHA2-512/256",
    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256",
]

# The sets that get the hedged and internal-interface cases.
HEDGED_SETS = ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s"]


def load(root, name):
    path = os.path.join(root, name)
    with open(path, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINS[name]:
        sys.exit(f"acvp-subset: {name}: SHA-256 {digest}, expected {PINS[name]}")
    return json.loads(data)


def joined(mode, root):
    """Each test of the prompt, merged with its expected result, with its group."""
    prompt = load(root, f"SLH-DSA-{mode}-FIPS205/prompt.json")
    results = load(root, f"SLH-DSA-{mode}-FIPS205/expectedResults.json")
    expected = {t["tcId"]: t for g in results["testGroups"] for t in g["tests"]}
    for group in prompt["testGroups"]:
        for test in group["tests"]:
            yield group, {**test, **expected[test["tcId"]]}


def hexfield(value):
    return value.upper() if value else "-"


def shortest(tests):
    return min(tests, key=lambda gt: (len(gt[1]["message"]), gt[1]["tcId"]))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: acvp-subset.py <ACVP-Server gen-val/json-files directory>")
    root = sys.argv[1]
    keygen = list(joined("keyGen", root))
    siggen = list(joined("sigGen", root))
    sigver = list(joined("sigVer", root))

    print("# Known answers for `make check`, selected from the NIST ACVP SLH-DSA")
    print("# vectors by tests/core/acvp-subset.py, which documents the selection")
    print("# and the line format.")
    print("#")
    print("# Source: https://github.com/usnistgov/ACVP-Server, gen-val/json-files,")
    print(f"# commit {ACVP_COMMIT} (tag {ACVP_TAG}).")
    print("# SHA-256 of the files read:")
    for name, digest in PINS.items():
        print(f"#   {digest}  {name}")
    print("#")
    print("# Changes (2026-10-13): this file selects test cases and writes one per")
    print("# line; the values are NIST's, unchanged. It is a derived work of NIST")
    print("# data, distributed under the NIST software notice in")
    print("# LICENSES/NIST-Software.txt.")

    assert len(HASH_ALGS) == len(SETS)
    for (name, sig_bytes), hash_alg in zip(SETS, HASH_ALGS):
        group, t = min(((g, t) for g, t in keygen if g["parameterSet"] == name),
                       key=lambda gt: gt[1]["tcId"])
        print("keygen", name, t["tcId"], *(hexfield(t[k]) for k in
              ("skSeed", "skPrf", "pkSeed", "pk", "sk")))

        for prehash in ("pure", "preHash"):
            group, t = shortest([(g, t) for g, t in siggen
                                 if g["parameterSet"] == name
                                 and g["signatureInterface"] == "external"
                                 and g["deterministic"] and g["preHash"] == prehash
                                 and (prehash == "pure" or t["hashAlg"] == hash_alg)])
            alg = "pure" if prehash == "pure" else t["hashAlg"]
            print("siggen", name, t["tcId"], alg, *(hexfield(t[k]) for k in
                  ("sk", "message", "context", "signature")))

        if name in HEDGED_SETS:
            group, t = shortest([(g, t) for g, t in siggen
                                 if g["parameterSet"] == name
                                 and g["signatureInterface"] == "external"
                                 and not g["deterministic"] and g["preHash"] == "pure"])
            print("hsiggen", name, t["tcId"], "pure", *(hexfield(t[k]) for k in
                  ("sk", "message", "context", "additionalRandomness", "signature")))
            group, t = shortest([(g, t) for g, t in siggen
                                 if g["parameterSet"] == name
                                 and g["signatureInterface"] == "internal"
                                 and not g["deterministic"]])
            print("isiggen", name, t["tcId"], *(hexfield(t[k]) for k in
                  ("sk", "message", "additionalRandomness", "signature")))

        group, t = shortest([(g, t) for g, t in sigver
                             if g["parameterSet"] == name
                             and g["signatureInterface"] == "external"
                             and not t["testPassed"]
                             and len(t["signature"]) == 2 * sig_bytes])
        alg = "pure" if group["preHash"] == "pure" else t["hashAlg"]
        print("sigver", name, t["tcId"], alg, int(t["testPassed"]), *(hexfield(t[k]) for k in
              ("pk", "message", "context", "signature")))


if __name__ == "__main__":
    main()
