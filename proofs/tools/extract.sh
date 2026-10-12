#!/bin/sh
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# extract.sh
#
# Extracts one (architecture, variant) EasyCrypt model of the hash sources
# with jasmin2ec and writes it, with generated-file headers, to
# OUTROOT/<arch>/<variant>/. Called by `make extract` (OUTROOT = extracted)
# and `make check-extraction` (OUTROOT = a scratch directory).
#
# Usage: JASMIN2EC=... HASH_SRC=... sh tools/extract.sh SPEC OUTROOT
#   SPEC  <arch>/<variant>:<jasmin arch>:<KeccakKernel>:<KeccakKernelX>:<Sha2Kernel>:<Sha2KernelX>
#         kernel fields are directories relative to HASH_SRC
# Run from proofs/. Exits non-zero if jasmin2ec fails or writes nothing.
#
# Output: HashExtracted.ec (the program) and the array theories it
# requires, each starting with a header that names the generator, the
# command and the SHA-256 of every Jasmin source read, so that a model can
# be traced to the sources it was extracted from.

set -eu

spec=$1
outroot=$2
: "${JASMIN2EC:?}" "${HASH_SRC:?}"

pair=${spec%%:*}
rest=${spec#*:}
jarch=$(echo "$rest" | cut -d: -f1)
kk=$(echo "$rest" | cut -d: -f2)
kkx=$(echo "$rest" | cut -d: -f3)
sk=$(echo "$rest" | cut -d: -f4)
skx=$(echo "$rest" | cut -d: -f5)
arch=${pair%%/*}

out="$outroot/$pair"
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$JASMIN2EC" --arch="$jarch" \
  -I Hash="$HASH_SRC" -I HashWord="$HASH_SRC/$arch" \
  -I KeccakKernel="$HASH_SRC/$kk" -I KeccakKernelX="$HASH_SRC/$kkx" \
  -I Sha2Kernel="$HASH_SRC/$sk" -I Sha2KernelX="$HASH_SRC/$skx" \
  -o "$work/HashExtracted.ec" extracted/hash.jazz

test -s "$work/HashExtracted.ec"

# Sources: the entry and every .jinc and .jazz under the hash tree, by path
# relative to HASH_SRC, sorted. Hashing the whole tree over-approximates
# what was read, which only makes the stale check stricter.
sources=$( (cd "$HASH_SRC" && find . \( -name '*.jinc' -o -name '*.jazz' \) | LC_ALL=C sort \
            | xargs shasum -a 256) \
           | sed 's/^/ *     /')
entry=$(shasum -a 256 < extracted/hash.jazz | cut -d' ' -f1)

for f in "$work"/*.ec; do
  name=$(basename "$f")
  {
    printf '(*\n'
    # The licence of the generated model (not of this script).
    # REUSE-IgnoreStart
    printf ' * SPDX-FileCopyrightText: nirapod-slhdsa contributors\n'
    printf ' * SPDX-License-Identifier: Apache-2.0\n'
    # REUSE-IgnoreEnd
    printf ' *\n'
    printf ' * GENERATED FILE. DO NOT EDIT.\n'
    printf ' *\n'
    printf ' * Generator:\n'
    printf ' *     jasmin2ec --arch=%s (array model: the jasmin2ec default)\n' "$jarch"
    printf ' *\n'
    printf ' * Model:\n'
    printf ' *     %s, kernels KeccakKernel=%s KeccakKernelX=%s Sha2Kernel=%s Sha2KernelX=%s\n' \
      "$pair" "$kk" "$kkx" "$sk" "$skx"
    printf ' *\n'
    printf ' * Regenerate:\n'
    printf ' *     make -C proofs extract     (check: make -C proofs check-extraction)\n'
    if [ "$name" = HashExtracted.ec ]; then
      printf ' *\n'
      printf ' * Entry proofs/extracted/hash.jazz SHA-256 %s\n' "$entry"
      printf ' * Sources under src/hash (SHA-256, path):\n'
      printf '%s\n' "$sources"
    fi
    printf ' *)\n\n'
    cat "$f"
  } > "$out/$name"
done
