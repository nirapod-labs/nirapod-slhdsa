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
# Usage: JASMIN2EC=... HASH_SRC=... SLHDSA_SRC=... [CORE_SETS=...] [PYTHON=...]
#        sh tools/extract.sh SPEC OUTROOT
#   SPEC  <arch>/<variant>:<jasmin arch>:<KeccakKernel>:<KeccakKernelX>:<Sha2Kernel>:<Sha2KernelX>
#         kernel fields are directories relative to HASH_SRC
#   CORE_SETS  parameter sets (names of SLHDSA_SRC/sets/<set>.jinc) whose
#         whole compilation unit is also extracted for this pair
# Run from proofs/. Exits non-zero if jasmin2ec fails or writes nothing.
#
# Output, one model per extraction entry:
#
#   HashExtracted.ec     extracted/hash.jazz, the hash sources under the
#                        pair's kernel roots
#   AddressExtracted.ec  extracted/address.jazz, the address code of the
#                        SLH-DSA core, which depends on no parameter set
#   sets/<set>/CoreExtracted.ec  for each set of CORE_SETS, the
#                        compilation unit sets/<set>.jinc the library
#                        builds, under the pair's kernel roots and the
#                        library's fault hook
#   sets/<set>/SetModel.ec  the names the per-set proofs use for that model
#                        (tools/set_model.py)
#
# and the array theories they require: those of the hash and address
# models in OUTROOT/<arch>/<variant>/, those of a set's model that are not
# among them in its sets/<set>/, so that the pair's models and each set's
# can be checked apart. Two models that use an array theory of the same
# name must produce the same file, or the script fails. Every
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
core_sets=${CORE_SETS:-}

"$JASMIN2EC" --arch="$jarch" \
  -I Hash="$HASH_SRC" -I HashWord="$HASH_SRC/$arch" \
  -I KeccakKernel="$HASH_SRC/$kk" -I KeccakKernelX="$HASH_SRC/$kkx" \
  -I Sha2Kernel="$HASH_SRC/$sk" -I Sha2KernelX="$HASH_SRC/$skx" \
  -o "$work/hash/HashExtracted.ec" extracted/hash.jazz
test -s "$work/hash/HashExtracted.ec"

"$JASMIN2EC" --arch="$jarch" -I Slhdsa="$SLHDSA_SRC" \
  -o "$work/address/AddressExtracted.ec" extracted/address.jazz
test -s "$work/address/AddressExtracted.ec"

# The parameter-set units, with the include roots the library compiles
# them under (top-level Makefile, JASMIN_INCLUDES; ci/kernel_roots.py
# checks that the roots agree).
for s in $core_sets; do
  mkdir "$work/core-$s"
  "$JASMIN2EC" --arch="$jarch" -I Slhdsa="$SLHDSA_SRC" -I SlhdsaHook="$SLHDSA_SRC/hook" \
    -I Hash="$HASH_SRC" -I HashWord="$HASH_SRC/$arch" \
    -I KeccakKernel="$HASH_SRC/$kk" -I KeccakKernelX="$HASH_SRC/$kkx" \
    -I Sha2Kernel="$HASH_SRC/$sk" -I Sha2KernelX="$HASH_SRC/$skx" \
    -I Sha2ThashX="$SLHDSA_SRC/thash_sha2_x4/single" \
    -o "$work/core-$s/CoreExtracted.ec" "$SLHDSA_SRC/sets/$s.jinc"
  test -s "$work/core-$s/CoreExtracted.ec"
  mkdir -p "$work/out/sets/$s"
  mv "$work/core-$s/CoreExtracted.ec" "$work/out/sets/$s/CoreExtracted.ec"
  "${PYTHON:-python3}" -I tools/set_model.py --set "$s" --params "$SLHDSA_SRC/params/$s.jinc" \
    --constants "$SLHDSA_SRC/constants.jinc" --model "$work/out/sets/$s/CoreExtracted.ec" \
    -o "$work/out/sets/$s/SetModel.ec"
done

# Merge the outputs. An array theory several models use must be the same
# file; the models share it on the load path. A set's array theory that
# the hash or address model also uses stays in the pair's directory, which
# is on the set's load path; any other goes to the set's directory.
for f in "$work"/hash/*.ec "$work"/address/*.ec; do
  name=$(basename "$f")
  if [ -e "$work/out/$name" ]; then
    cmp -s "$f" "$work/out/$name" \
      || { echo "extract.sh: $name differs between the models" >&2; exit 1; }
  else
    cp "$f" "$work/out/$name"
  fi
done
for s in $core_sets; do
  for f in "$work/core-$s"/*.ec; do
    [ -e "$f" ] || continue
    name=$(basename "$f")
    if [ -e "$work/out/$name" ]; then
      cmp -s "$f" "$work/out/$name" \
        || { echo "extract.sh: $name differs between the models" >&2; exit 1; }
    else
      cp "$f" "$work/out/sets/$s/$name"
    fi
  done
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

core_sources=$( (cd "$SLHDSA_SRC" && find . \( -name '*.jinc' -o -name '*.jazz' \) | LC_ALL=C sort \
            | xargs shasum -a 256) \
           | sed 's/^/ *     /')

for f in "$work"/out/*.ec "$work"/out/sets/*/*.ec; do
  [ -e "$f" ] || continue
  name=${f#"$work/out/"}
  set=${name#sets/}; set=${set%%/*}
  mkdir -p "$(dirname "$out/$name")"
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
    case $name in
      sets/*/SetModel.ec)
        printf ' *     tools/set_model.py, from src/slhdsa/params/%s.jinc, src/slhdsa/constants.jinc\n' "$set"
        printf ' *     and the array theories CoreExtracted.ec requires\n';;
      *)
        printf ' *     jasmin2ec --arch=%s (array model: the jasmin2ec default)\n' "$jarch";;
    esac
    printf ' *\n'
    printf ' * Model:\n'
    case $name in
      HashExtracted.ec|sets/*/CoreExtracted.ec|sets/*/SetModel.ec)
        printf ' *     %s, kernels KeccakKernel=%s KeccakKernelX=%s Sha2Kernel=%s Sha2KernelX=%s\n' \
          "$pair" "$kk" "$kkx" "$sk" "$skx";;
      *)
        printf ' *     %s\n' "$pair";;
    esac
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
      sets/*/CoreExtracted.ec|sets/*/SetModel.ec)
        printf ' *\n'
        printf ' * Entry src/slhdsa/sets/%s.jinc\n' "$set"
        printf ' * Sources under src/slhdsa (SHA-256, path):\n'
        printf '%s\n' "$core_sources"
        printf ' * Sources under src/hash (SHA-256, path):\n'
        printf '%s\n' "$hash_sources";;
    esac
    printf ' *)\n\n'
    cat "$f"
  } > "$out/$name"
done
