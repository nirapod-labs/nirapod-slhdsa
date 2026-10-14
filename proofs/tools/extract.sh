#!/bin/sh
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# extract.sh
#
# Extracts the EasyCrypt models of one (architecture, variant) pair with
# jasmin2ec and writes them, with generated-file headers, to
# OUTROOT/<arch>/<variant>/. Called by `make extract` (OUTROOT = extracted)
# and `make check-extraction` (OUTROOT = a scratch directory).
#
# Usage: JASMIN2EC=... HASH_SRC=... SLHDSA_SRC=... sh tools/extract.sh SPEC OUTROOT
#   SPEC  <arch>/<variant>:<jasmin arch>:<KeccakKernel>:<KeccakKernelX>:<Sha2Kernel>:<Sha2KernelX>
#         kernel fields are directories relative to HASH_SRC
# Run from proofs/. Exits non-zero if jasmin2ec fails or writes nothing.
#
# Output, one model per extraction entry:
#
#   HashExtracted.ec     extracted/hash.jazz, the hash sources under the
#                        pair's kernel roots
#   AddressExtracted.ec  extracted/address.jazz, the address code of the
#                        SLH-DSA core, which depends on no parameter set
#
# and the array theories they require. Two models that use an array theory
# of the same name must produce the same file, or the script fails. Every
# file starts with a header that names the generator, the command and the
# SHA-256 of the Jasmin sources read, so that a model can be traced to the
# sources it was extracted from.

set -eu

spec=$1
outroot=$2
: "${JASMIN2EC:?}" "${HASH_SRC:?}" "${SLHDSA_SRC:?}"

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

mkdir "$work/hash" "$work/address" "$work/out"

"$JASMIN2EC" --arch="$jarch" \
  -I Hash="$HASH_SRC" -I HashWord="$HASH_SRC/$arch" \
  -I KeccakKernel="$HASH_SRC/$kk" -I KeccakKernelX="$HASH_SRC/$kkx" \
  -I Sha2Kernel="$HASH_SRC/$sk" -I Sha2KernelX="$HASH_SRC/$skx" \
  -o "$work/hash/HashExtracted.ec" extracted/hash.jazz
test -s "$work/hash/HashExtracted.ec"

"$JASMIN2EC" --arch="$jarch" -I Slhdsa="$SLHDSA_SRC" \
  -o "$work/address/AddressExtracted.ec" extracted/address.jazz
test -s "$work/address/AddressExtracted.ec"

# Merge the two outputs. An array theory both models use must be the same
# file; the models share it on the load path.
for f in "$work"/hash/*.ec "$work"/address/*.ec; do
  name=$(basename "$f")
  if [ -e "$work/out/$name" ]; then
    cmp -s "$f" "$work/out/$name" \
      || { echo "extract.sh: $name differs between the models" >&2; exit 1; }
  else
    cp "$f" "$work/out/$name"
  fi
done

# Sources of the hash model: the entry and every .jinc and .jazz under the
# hash tree, by path relative to HASH_SRC, sorted. Hashing the whole tree
# over-approximates what was read, which only makes the stale check
# stricter.
hash_sources=$( (cd "$HASH_SRC" && find . \( -name '*.jinc' -o -name '*.jazz' \) | LC_ALL=C sort \
            | xargs shasum -a 256) \
           | sed 's/^/ *     /')
hash_entry=$(shasum -a 256 < extracted/hash.jazz | cut -d' ' -f1)

# Sources of the address model: the files the entry requires from the core
# tree. They must require nothing themselves, so that this list is every
# Jasmin source the model was extracted from.
address_files=$(sed -n 's/^from Slhdsa require "\([^"]*\)".*/\1/p' extracted/address.jazz | LC_ALL=C sort)
test -n "$address_files"
for f in $address_files; do
  if grep -q '^[[:space:]]*\(from [A-Za-z_]* \)\{0,1\}require' "$SLHDSA_SRC/$f"; then
    echo "extract.sh: $f requires other files; list them in the header" >&2
    exit 1
  fi
done
address_sources=$( (cd "$SLHDSA_SRC" && printf './%s\n' $address_files | xargs shasum -a 256) \
           | sed 's/^/ *     /')
address_entry=$(shasum -a 256 < extracted/address.jazz | cut -d' ' -f1)

for f in "$work"/out/*.ec; do
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
    case $name in
      HashExtracted.ec)
        printf ' *\n'
        printf ' * Entry proofs/extracted/hash.jazz SHA-256 %s\n' "$hash_entry"
        printf ' * Sources under src/hash (SHA-256, path):\n'
        printf '%s\n' "$hash_sources";;
      AddressExtracted.ec)
        printf ' *\n'
        printf ' * Entry proofs/extracted/address.jazz SHA-256 %s\n' "$address_entry"
        printf ' * Sources under src/slhdsa (SHA-256, path):\n'
        printf '%s\n' "$address_sources";;
    esac
    printf ' *)\n\n'
    cat "$f"
  } > "$out/$name"
done
