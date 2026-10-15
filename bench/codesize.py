# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/codesize.py
# =================
#
# Code and data size of a static library, read from the section headers
# of its object files, so the result does not depend on which `size` tool
# a host has (their formats and section classes differ between platforms).
#
#   python3 -I bench/codesize.py <library.a>
#
# prints one JSON object: the totals and one entry per archive member.
# Sections are classed by their attributes, not their names:
#
#   code     executable                  Mach-O: S_ATTR_PURE_INSTRUCTIONS or
#                                        S_ATTR_SOME_INSTRUCTIONS
#                                        ELF: SHF_ALLOC and SHF_EXECINSTR
#   rodata   allocated, not writable     Mach-O: segment __TEXT, not code
#                                        ELF: SHF_ALLOC without SHF_WRITE
#   data     allocated and writable      Mach-O: __DATA* segments
#                                        ELF: SHF_ALLOC and SHF_WRITE
#   bss      zero-filled                 Mach-O: S_ZEROFILL, S_GB_ZEROFILL
#                                        ELF: SHT_NOBITS
#
# Sections the loader does not map (symbol tables, relocations, debug
# information, unwind data on Mach-O's __LD segment) are not counted.
# Unwind and exception tables that are mapped (ELF .eh_frame, Mach-O
# __TEXT,__eh_frame) count as rodata. Supported: 64-bit little-endian
# Mach-O and ELF objects in a System V or BSD ar archive.

import json
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
S_ZEROFILL, S_GB_ZEROFILL = 0x1, 0xC
S_ATTR_CODE = 0x80000000 | 0x00000400
SHT_NOBITS = 8
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4


class Failure(Exception):
    pass


def members(blob):
    """(name, bytes) of each object member of an ar archive."""
    if not blob.startswith(b"!<arch>\n"):
        raise Failure("not an ar archive")
    pos, names = 8, b""
    while pos + 60 <= len(blob):
        head = blob[pos:pos + 60]
        name, size = head[:16].decode().rstrip(), int(head[48:58])
        body = blob[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
        if name.startswith("#1/"):          # BSD: the name precedes the data
            k = int(name[3:])
            name, body = body[:k].rstrip(b"\0").decode(), body[k:]
        elif name == "//":                  # System V long-name table
            names = body
            continue
        elif name.startswith("/") and name[1:].isdigit():
            k = int(name[1:])
            name = names[k:names.index(b"/\n", k)].decode()
        elif name in ("/", "/SYM64/"):        # System V symbol tables
            continue
        if name.startswith("__.SYMDEF"):      # BSD symbol table
            continue
        yield name.rstrip("/"), body


def macho(obj):
    sizes = dict(code=0, rodata=0, data=0, bss=0)
    ncmds = struct.unpack_from("<I", obj, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", obj, off)
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<I", obj, off + 64)[0]
            for k in range(nsects):
                s = off + 72 + 80 * k
                seg = obj[s + 16:s + 32].rstrip(b"\0").decode()
                size = struct.unpack_from("<Q", obj, s + 40)[0]
                flags = struct.unpack_from("<I", obj, s + 64)[0]
                if flags & 0xFF in (S_ZEROFILL, S_GB_ZEROFILL):
                    sizes["bss"] += size
                elif flags & S_ATTR_CODE:
                    sizes["code"] += size
                elif seg == "__TEXT":
                    sizes["rodata"] += size
                elif seg.startswith("__DATA"):
                    sizes["data"] += size
        off += cmdsize
    return sizes


def elf(obj):
    sizes = dict(code=0, rodata=0, data=0, bss=0)
    if obj[4] != 2 or obj[5] != 1:
        raise Failure("only 64-bit little-endian ELF is supported")
    shoff = struct.unpack_from("<Q", obj, 0x28)[0]
    shentsize, shnum = struct.unpack_from("<HH", obj, 0x3A)
    for k in range(shnum):
        s = shoff + k * shentsize
        sh_type, sh_flags = struct.unpack_from("<IQ", obj, s + 4)
        size = struct.unpack_from("<Q", obj, s + 32)[0]
        if not sh_flags & SHF_ALLOC:
            continue
        if sh_type == SHT_NOBITS:
            sizes["bss"] += size
        elif sh_flags & SHF_EXECINSTR:
            sizes["code"] += size
        elif sh_flags & SHF_WRITE:
            sizes["data"] += size
        else:
            sizes["rodata"] += size
    return sizes


def library_size(path):
    with open(path, "rb") as f:
        blob = f.read()
    total = dict(code=0, rodata=0, data=0, bss=0)
    each = []
    for name, obj in members(blob):
        if obj[:4] == b"\x7fELF":
            s = elf(obj)
        elif struct.unpack_from("<I", obj, 0)[0] == MH_MAGIC_64:
            s = macho(obj)
        else:
            raise Failure(f"{name}: not a 64-bit Mach-O or ELF object")
        each.append(dict(member=name, **s))
        for key in total:
            total[key] += s[key]
    return dict(total=total, members=each)


def main(argv):
    if len(argv) != 2:
        print("usage: codesize.py <library.a>", file=sys.stderr)
        return 2
    try:
        print(json.dumps(library_size(argv[1]), indent=1))
    except (Failure, OSError, struct.error, ValueError) as e:
        print(f"codesize: {argv[1]}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
