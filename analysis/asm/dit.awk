# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# analysis/asm/dit.awk
# ====================
#
# The timing rule of check-asm.sh on AArch64, on one unit's assembly
# (awk -f dit.awk <unit.s>): every instruction is one that the Arm
# architecture lists as a data-independent-time instruction, or one of the
# forms below that consumes no secret by construction. One line per
# violation, "<file>: <message>"; nothing when the file passes.
#
# Source: Arm Architecture Reference Manual for A-profile architecture,
# ARM DDI 0487 issue M.d, B1.5.6 "About PSTATE.DIT". While PSTATE.DIT is
# set, the execution time of a data-independent-time instruction does not
# depend on the data values it consumes or produces, except a value used
# to form a memory address. An instruction is one exactly when the
# Operational information of its description (chapters C6 and C7) says
# so. Each form below names that description. An alias (MOV, CMP, LSL,
# MUL, ...) is the instruction it stands for and is listed with it. The
# list agrees with the Operational information of the Arm A64 ISA XML,
# release 2026-03, on every instruction but MOVK: DIT in DDI 0487 M.d, no
# statement in the XML. MOVK is therefore held to the constant rule below,
# which does not depend on either answer.
#
# A form is the mnemonic and the classes of its operands, comma-separated:
#
#     X W        general register 0-30, 64 or 32 bits (lr included)
#     SP         the stack pointer
#     V.<T>      vector register with arrangement <T>; V.<e>[i] an element
#     Q          128-bit SIMD&FP register
#     #          immediate
#     M          memory operand, with any pre- or post-index; its address
#                is public by the constant-time check and outside DIT
#     S          symbol or label, with any relocation operator
#     lsl # ...  shift, COND condition, sy barrier option
#
# Forms accepted without being data-independent-time instructions:
#
#     constant  MOVZ, MOVN, and MOV with an immediate (their alias): the
#               result is the immediate and no register is read. MOVK
#               only directly after MOVZ, MOVN, MOV with an immediate or
#               MOVK of the same register, with no label between, so it
#               reads only the constant being built
#     address   ADRP: the page address of a data symbol, from the PC
#     branch    B, BL, RET: a label of the unit or the return address
#               (exports.awk keeps both inside the unit); B.<cond> reads
#               the flags, and a branch condition is public by the
#               constant-time check
#     barrier   DSB SY, ISB, CSDB: no data operand
#
# What it does not establish: that no secret reaches B.<cond> or an
# address is the constant-time check of the source (analysis/ct), not
# this rule; that the CPU honours DIT is the CPU's, and the C layer sets
# PSTATE.DIT only where FEAT_DIT is implemented (capi/timing.c).

function norm(s) {
  sub(/^[ \t]+/, "", s)
  sub(/[ \t]+$/, "", s)
  gsub(/[ \t]+/, " ", s)
  gsub(/, /, ",", s)
  return s
}

function bad(msg) {
  print FILENAME ": " msg
}

# Splits the operand list s at the commas outside brackets into ops[1..n].
function split_ops(s, ops,    i, c, depth, cur, n) {
  n = 0
  depth = 0
  cur = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "[") depth++
    if (c == "]") depth--
    if (c == "," && depth == 0) { ops[++n] = cur; cur = "" }
    else cur = cur c
  }
  if (cur != "") ops[++n] = cur
  return n
}

function class(o) {
  if (o ~ /^\[/) return "M"
  if (o ~ /^#-?[0-9]+$/ || o ~ /^#0x[0-9a-f]+$/) return "#"
  if (o == "sp") return "SP"
  if (o == "lr" || o == "fp") return "X"
  if (o ~ /^x([0-9]|[12][0-9]|30)$/) return "X"
  if (o ~ /^w([0-9]|[12][0-9]|30)$/) return "W"
  if (o ~ /^v([0-9]|[12][0-9]|3[01])\.[0-9]*[bhsd]$/) return "V." substr(o, index(o, ".") + 1)
  if (o ~ /^v([0-9]|[12][0-9]|3[01])\.[bhsd]\[[0-9]+\]$/) return "V." substr(o, index(o, ".") + 1, 1) "[i]"
  if (o ~ /^q([0-9]|[12][0-9]|3[01])$/) return "Q"
  if (o ~ /^(lsl|lsr|asr|ror) #[0-9]+$/) return substr(o, 1, 3) " #"
  if (o ~ /^(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)$/) return "COND"
  if (o == "sy") return "sy"
  if (o ~ /^(:lo12:)?[A-Za-z_.$][A-Za-z0-9_.$]*(@PAGE|@PAGEOFF)?(\+[0-9]+)?$/) return "S"
  return "?"
}

# list(T, SECTION, FORMS): each "|"-separated form of FORMS goes into
# table T, recorded with SECTION.
function list(t, section, forms,    f, n, i) {
  n = split(forms, f, "|")
  for (i = 1; i <= n; i++) {
    if (t == "dit") dit[f[i]] = section
    else public[f[i]] = section
  }
}

BEGIN {
  list("dit", "C6.2.5 ADD (immediate)", "add X,X,#|add W,W,#|add X,SP,#|add SP,SP,#|add X,X,S")
  list("dit", "C6.2.278 MOV (to/from SP), alias of ADD (immediate)", "mov SP,X|mov X,SP")
  list("dit", "C6.2.6 ADD (shifted register)", "add X,X,X|add W,W,W")
  list("dit", "C6.2.4 ADD (extended register)", "add SP,SP,X")
  list("dit", "C7.2.2 ADD (vector)", "add V.2d,V.2d,V.2d|add V.4s,V.4s,V.4s")
  list("dit", "C6.2.14 AND (immediate)", "and X,X,#|and W,W,#")
  list("dit", "C6.2.15 AND (shifted register)", "and X,X,X|and W,W,W")
  list("dit", "C6.2.41 BIC (shifted register)", "bic X,X,X")
  list("dit", "C6.2.155 EOR (immediate)", "eor X,X,#|eor W,W,#")
  list("dit", "C6.2.156 EOR (shifted register)", "eor X,X,X|eor W,W,W|eor X,X,X,ror #")
  list("dit", "C7.2.43 EOR (vector)", "eor V.16b,V.16b,V.16b")
  list("dit", "C6.2.302 ORR (shifted register)", "orr X,X,X|orr W,W,W")
  list("dit", "C6.2.282 MOV (register), alias of ORR (shifted register)", "mov X,X|mov W,W")
  list("dit", "C7.2.245 MOV (vector), alias of C7.2.256 ORR (vector, register)", "mov V.16b,V.16b")
  list("dit", "C6.2.457 SUB (immediate)", "sub SP,SP,#|sub X,SP,#|sub X,X,#")
  list("dit", "C6.2.456 SUB (extended register)", "sub SP,SP,X")
  list("dit", "C6.2.458 SUB (shifted register)", "sub X,X,X|sub W,W,W")
  list("dit", "C6.2.295 NEG (shifted register), alias of SUB (shifted register)", "neg X,X")
  list("dit", "C6.2.464 SUBS (immediate)", "subs X,X,#")
  list("dit", "C6.2.96 CMP (immediate), alias of SUBS (immediate)", "cmp X,#|cmp W,#")
  list("dit", "C6.2.97 CMP (shifted register), alias of C6.2.465 SUBS (shifted register)", "cmp X,X|cmp W,W")
  list("dit", "C6.2.138 CSEL", "csel X,X,X,COND|csel W,W,W,COND")
  list("dit", "C6.2.293 MUL, alias of C6.2.275 MADD", "mul X,X,X")
  list("dit", "C6.2.270 LSL (immediate), alias of C6.2.487 UBFM", "lsl X,X,#|lsl W,W,#")
  list("dit", "C6.2.273 LSR (immediate), alias of C6.2.487 UBFM", "lsr X,X,#|lsr W,W,#")
  list("dit", "C6.2.347 ROR (immediate), alias of C6.2.160 EXTR", "ror X,X,#|ror W,W,#")
  list("dit", "C6.2.342 REV", "rev X,X|rev W,W")
  list("dit", "C6.2.216 LDR (immediate), C6.2.218 LDR (register)", "ldr X,M|ldr W,M")
  list("dit", "C6.2.220 LDRB (immediate), C6.2.221 LDRB (register)", "ldrb W,M")
  list("dit", "C7.2.230 LDR (immediate, SIMD&FP), C7.2.232 LDR (register, SIMD&FP)", "ldr Q,M")
  list("dit", "C6.2.415 STR (immediate), C6.2.416 STR (register)", "str X,M|str W,M")
  list("dit", "C6.2.417 STRB (immediate), C6.2.418 STRB (register)", "strb W,M")
  list("dit", "C7.2.387 STR (immediate, SIMD&FP), C7.2.388 STR (register, SIMD&FP)", "str Q,M")
  list("dit", "C7.2.41 DUP (general)", "dup V.2d,X")
  list("dit", "C7.2.430 UMOV", "umov X,V.d[i]")
  list("dit", "C7.2.44 EXT", "ext V.16b,V.16b,V.16b,#")
  list("dit", "C7.2.263 REV32 (vector)", "rev32 V.16b,V.16b")
  list("dit", "C7.2.264 REV64", "rev64 V.16b,V.16b")
  list("dit", "C7.2.12 BCAX", "bcax V.16b,V.16b,V.16b,V.16b")
  list("dit", "C7.2.42 EOR3", "eor3 V.16b,V.16b,V.16b,V.16b")
  list("dit", "C7.2.260 RAX1", "rax1 V.2d,V.2d,V.2d")
  list("dit", "C7.2.460 XAR", "xar V.2d,V.2d,V.2d,#")
  list("dit", "C7.2.290 SHA256H", "sha256h Q,Q,V.4s")
  list("dit", "C7.2.289 SHA256H2", "sha256h2 Q,Q,V.4s")
  list("dit", "C7.2.291 SHA256SU0", "sha256su0 V.4s,V.4s")
  list("dit", "C7.2.292 SHA256SU1", "sha256su1 V.4s,V.4s,V.4s")
  list("dit", "C7.2.294 SHA512H", "sha512h Q,Q,V.2d")
  list("dit", "C7.2.293 SHA512H2", "sha512h2 Q,Q,V.2d")
  list("dit", "C7.2.295 SHA512SU0", "sha512su0 V.2d,V.2d")
  list("dit", "C7.2.296 SHA512SU1", "sha512su1 V.2d,V.2d,V.2d")

  list("public", "constant", "movz X,#|movz W,#|movn X,#|movn W,#|mov X,#")
  list("public", "address", "adrp X,S")
  list("public", "branch", "b S|bl S|b.cond S|ret")
  list("public", "barrier", "dsb sy|isb|csdb")

  constant = ""
}

{
  line = $0
  sub(/\/\/.*/, "", line)                      # comment
  line = norm(line)
  if (line == "") next
  if (line ~ /:$/) { constant = ""; next }     # a label: a constant chain ends
  if (line ~ /^\./) next                       # directive

  m = index(line, " ") ? substr(line, 1, index(line, " ") - 1) : line
  n = index(line, " ") ? split_ops(substr(line, index(line, " ") + 1), ops) : 0
  form = m ~ /^b\.[a-z]+$/ ? "b.cond" : m
  for (i = 1; i <= n; i++) {
    c = class(ops[i])
    if (c == "#" && i > 1 && class(ops[i - 1]) == "M") continue   # post-index
    form = form (i == 1 ? " " : ",") c
  }

  dest = n > 0 ? ops[1] : ""
  if (form == "movk X,#,lsl #" || form == "movk W,#,lsl #") {
    if (dest != constant) bad("movk on a register that does not hold a constant (" line ")")
  } else if (!(form in dit) && !(form in public)) {
    bad("instruction outside the data-independent-time list (" line ")")
  }
  constant = (m ~ /^mov[znk]?$/ && form ~ /,#/ && form !~ /,#,/ || m == "movk") ? dest : ""
}
