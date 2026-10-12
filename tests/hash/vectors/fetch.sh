#!/bin/sh
#
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# Fetch the NIST CAVP byte-oriented hash and HMAC response files into the
# directory given as the only argument, after checking each archive against
# the SHA-256 pinned below. Network access is required; nothing else is
# read from outside this script.
#
# The archives are US Government works (NIST CAVP) and are not stored in
# the repository. A hash mismatch, a failed download or a missing tool
# stops the script with a non-zero status and leaves no extracted files.

set -eu

dest=${1:?usage: fetch.sh <directory>}
base=https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents

# archive path under $base                 SHA-256 of the archive
pins="
shs/shabytetestvectors.zip      929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8
sha3/sha-3bytetestvectors.zip   cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c
sha3/shakebytetestvectors.zip   debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7
mac/hmactestvectors.zip         418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd
"

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "$pins" | while read -r path want; do
  [ -n "$path" ] || continue
  zip="$tmp/$(basename "$path")"
  curl -fsSL --max-time 300 -o "$zip" "$base/$path"
  got=$(sha256 "$zip")
  if [ "$got" != "$want" ]; then
    echo "fetch.sh: $path: SHA-256 $got, expected $want" >&2
    exit 1
  fi
  unzip -q -o -j "$zip" '*.rsp' -d "$tmp/rsp"
done

mkdir -p "$dest"
mv "$tmp"/rsp/*.rsp "$dest"/
echo "fetch.sh: $(ls "$dest" | wc -l | tr -d ' ') response files in $dest"
