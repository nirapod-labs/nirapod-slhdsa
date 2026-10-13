- `toolchain/build.sh` writes `cil.sha256`, `admit-scan.log` and
  `eclib-axioms.log` sorted, so that builds of the same compiler on different
  hosts produce byte-identical records. They used to follow the shell's locale
  and the file system's directory order.
- The admit scans of `toolchain/build.sh` read files byte-wise in the C
  locale. In a UTF-8 locale, GNU grep skipped the matching lines of a file
  holding an invalid byte or a NUL, so an admit there could go unlisted.
