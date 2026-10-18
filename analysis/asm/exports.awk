# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# analysis/asm/exports.awk
# ========================
#
# The control-flow rules of check-asm.sh, on one unit's assembly
# (awk -v arch=aarch64|x86_64 -f exports.awk <unit.s>). One line per
# violation, "<file>: <message>"; nothing when the file passes. With
# -v frames=1 it also prints the size each export's epilogue zeroes.
#
#     branches  every branch and call names a label of this file: no call
#               into other code, no tail call out of the unit, no
#               indirect branch or call
#     traps     no system call or other trap instruction; on AArch64 no
#               system-register access (MSR, MRS): the timing mode
#               (PSTATE.DIT) belongs to the C layer, which sets it around
#               the call and restores it after
#     fence     every export runs a speculation barrier before its first
#               call: the initialisation of the misspeculation flag
#               (AArch64 DSB SY and ISB, x86-64 LFENCE)
#     leave     every export reaches its RET only through the
#               stack-zeroing epilogue of jasminc -stack-zero loop
#               -stack-zero-size u64, as written below, so the epilogue is
#               its one way out. The export ends at its first RET. Until
#               then it branches only to its own local labels, each defined
#               before that RET; after it, no label of the export appears
#               anywhere in the file, and no code outside the exports
#               branches to one
#     data      no data directive (.byte, .inst, .long, ...) in a code
#               section: an instruction written as raw bytes would escape
#               every rule here and in dit.awk
#
# The epilogue, with any registers in the places of S, C, A, R and any
# label L, Z a positive multiple of 8:
#
#     AArch64                         x86-64
#     mov    S, sp                    movq   %rsp, S
#     movz   C, #Z                    andq   $-K, %rsp
#     and    A, S, #<-16>             subq   $Z, %rsp
#     mov    sp, A                    movq   $Z, C
#     sub    sp, sp, C              L:
#     mov    R, #0                    subq   $8, C
#   L:                                movq   $0, (%rsp,C)
#     subs   C, C, #8                 jne    L
#     str    R, [sp, C]               movq   S, %rsp
#     b.ne   L                        ret
#     mov    sp, S
#     ldr    x30, [sp], #16
#     ret
#
# It stores zero in every 8-byte word of the Z bytes below the stack
# pointer at the epilogue, aligned down, then returns with that stack
# pointer. The pattern does not show that this is the stack pointer of
# the entry (the compiler restores it before the epilogue) or that Z
# covers the frame: both are the compiler's computation, and tests/abi/
# test_stack.c measures the result on the running host (no residue below
# the return slot).

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

# The operand list of instruction s ("op a,b,c" -> "a,b,c").
function operands(s) {
  return index(s, " ") ? substr(s, index(s, " ") + 1) : ""
}

function mnemonic(s) {
  return index(s, " ") ? substr(s, 1, index(s, " ") - 1) : s
}

# The last operand: the target of a branch.
function target(s,    o, n, parts) {
  o = operands(s)
  n = split(o, parts, ",")
  return parts[n]
}

function is_branch(m) {
  if (arch == "aarch64") return m ~ /^(b|bl|b\.[a-z]+|cbn?z|tbn?z)$/
  return m ~ /^(j[a-z]+|callq?)$/
}

function is_call(m) {
  return arch == "aarch64" ? m == "bl" : m ~ /^callq?$/
}

function is_indirect(s, m) {
  if (arch == "aarch64") return m ~ /^(blr|br)[a-z]*$/
  return (m ~ /^(j[a-z]+|callq?)$/ && operands(s) ~ /^\*/)
}

function is_trap(m) {
  if (arch == "aarch64") return m ~ /^(svc|hvc|smc|brk|hlt|msr|mrs)$/
  return m ~ /^(syscall|sysenter|sysexit|sysret[lq]?|int|int1|int3|into|icebp|ud0|ud1|ud2|hlt|rdmsr|wrmsr)$/
}

# 1 if directive line s emits bytes into the section: data, padding with
# a value, or an instruction encoding.
function is_data(s) {
  return s ~ /^\.(inst|byte|short|hword|word|long|int|quad|octa|value|[248]byte|ascii|asciz|string|zero|fill|space|skip|incbin)( |$)/
}

# 1 if directive line s switches to a code section.
function code_section(s) {
  if (s ~ /^\.text( |$)/) return 1
  if (s ~ /^\.section /) return s ~ /^\.section (__TEXT,__text|\.text)(,|$)/
  return -1
}

# The label prefix shared by an export's local labels: "L<symbol>$" of
# label l, or "" when l is not such a label.
function label_base(l) {
  sub(/^\./, "", l)
  if (l !~ /^L_?nirapod_slhdsa_jz_[A-Za-z0-9_]+\$[0-9]+$/) return ""
  sub(/\$[0-9]+$/, "$", l)
  return l
}

# 1 if lines body[k - 12 .. k - 1] are the AArch64 epilogue, k the RET.
function epilogue_aarch64(k,    S, C, A, R, Z, L) {
  if (k < 13) return 0
  if (body[k - 12] !~ /^mov [xw][0-9]+,sp$/) return 0
  S = substr(body[k - 12], 5, index(body[k - 12], ",") - 5)
  if (body[k - 11] !~ /^movz x[0-9]+,#[0-9]+$/) return 0
  C = substr(body[k - 11], 6, index(body[k - 11], ",") - 6)
  Z = substr(body[k - 11], index(body[k - 11], "#") + 1) + 0
  if (Z <= 0 || Z % 8 != 0) return 0
  if (body[k - 10] !~ /^and x[0-9]+,x[0-9]+,#[0-9]+$/) return 0
  A = substr(body[k - 10], 5, index(body[k - 10], ",") - 5)
  if (index(body[k - 10], "and " A "," S ",#") != 1) return 0
  if (body[k - 9] != "mov sp," A) return 0
  if (body[k - 8] != "sub sp,sp," C) return 0
  if (body[k - 7] !~ /^mov x[0-9]+,#0$/) return 0
  R = substr(body[k - 7], 5, index(body[k - 7], ",") - 5)
  if (body[k - 6] !~ /:$/) return 0
  L = substr(body[k - 6], 1, length(body[k - 6]) - 1)
  if (body[k - 5] != "subs " C "," C ",#8") return 0
  if (body[k - 4] != "str " R ",[sp," C "]") return 0
  if (body[k - 3] != "b.ne " L) return 0
  if (body[k - 2] != "mov sp," S) return 0
  if (body[k - 1] != "ldr x30,[sp],#16") return 0
  zero_size = Z
  return 1
}

# 1 if lines body[k - 9 .. k - 1] are the x86-64 epilogue, k the RET.
function epilogue_x86_64(k,    S, C, Z, L) {
  if (k < 10) return 0
  if (body[k - 9] !~ /^movq %rsp,%r[a-z0-9]+$/) return 0
  S = substr(body[k - 9], length("movq %rsp,") + 1)
  if (body[k - 8] !~ /^andq \$-[0-9]+,%rsp$/) return 0
  if (body[k - 7] !~ /^subq \$[0-9]+,%rsp$/) return 0
  Z = substr(body[k - 7], 7, index(body[k - 7], ",") - 7) + 0
  if (Z <= 0 || Z % 8 != 0) return 0
  if (body[k - 6] !~ /^movq \$[0-9]+,%r[a-z0-9]+$/) return 0
  if (substr(body[k - 6], 7, index(body[k - 6], ",") - 7) + 0 != Z) return 0
  C = substr(body[k - 6], index(body[k - 6], ",") + 1)
  if (body[k - 5] !~ /:$/) return 0
  L = substr(body[k - 5], 1, length(body[k - 5]) - 1)
  if (body[k - 4] != "subq $8," C) return 0
  if (body[k - 3] != "movq $0,(%rsp," C ")") return 0
  if (body[k - 2] != "jne " L) return 0
  if (body[k - 1] != "movq " S ",%rsp") return 0
  zero_size = Z
  return 1
}

# Close the export in progress at its RET (k) or at the end of the file.
# Every branch it took must land on a label it defined before the RET.
function close_export(k,    ok, i) {
  ok = 0
  if (k > 0) ok = arch == "aarch64" ? epilogue_aarch64(k) : epilogue_x86_64(k)
  if (!ok) bad(export_op " does not clear its stack before returning")
  else if (frames) print FILENAME ": " export_op " zeroes " zero_size " bytes"
  if (!fenced) bad(export_op " has no speculation barrier before its first call")
  for (i = 1; i <= nt; i++) {
    if (!(jumps[i] in own)) bad(export_op " branches past its return (" jump_line[i] ")")
  }
  closed[local] = export_op
  in_export = 0
}

BEGIN { in_export = 0; nb = 0; no = 0; code = 1 }

{
  line = norm($0)
  if (line ~ /^\./ && line !~ /:$/) {                     # directive
    c = code_section(line)
    if (c >= 0) code = c
    else if (line ~ /^\.(data|bss|const|rodata|cstring)( |$)/) code = 0
    if (code && is_data(line)) bad("data directive in a code section (" line ")")
    next
  }
  if (line == "") next

  if (line ~ /:$/) {
    lbl = substr(line, 1, length(line) - 1)
    defined[lbl] = 1
    if (lbl ~ /^_?nirapod_slhdsa_jz_[A-Za-z0-9_]+__[a-z_]+$/) {
      if (in_export) close_export(0)
      in_export = 1
      export_op = lbl
      sub(/^.*__/, "", export_op)
      sym = lbl
      sub(/^_/, "", sym)
      local = "L" sym "$"
      fenced = 0
      called = 0
      dsb = 0
      n = 0
      nt = 0
      split("", own)
      next
    }
    base = label_base(lbl)
    if (base in closed) bad(closed[base] " has code after its return (" line ")")
    if (in_export) {
      t = lbl
      sub(/^\./, "", t)
      own[t] = 1
    }
  }

  m = mnemonic(line)
  if (is_indirect(line, m)) bad("indirect branch or call (" line ")")
  if (is_trap(m)) bad("trap or system-register instruction (" line ")")
  if (is_branch(m)) {
    branches[++nb] = target(line)
    t = target(line)
    sub(/^\./, "", t)
    if (in_export && !is_call(m)) {
      if (index(t, local) != 1) bad(export_op " branches out of the export (" line ")")
      jumps[++nt] = t
      jump_line[nt] = line
    } else if (!in_export && !is_call(m)) {
      outside[++no] = t
      outside_line[no] = line
    }
  }

  if (!in_export) next
  body[++n] = line
  if (!called) {
    if (arch == "aarch64") {
      if (line == "dsb sy") dsb = 1
      if (dsb && line == "isb") fenced = 1
    } else if (line == "lfence") {
      fenced = 1
    }
  }
  if (is_call(m)) called = 1
  if (m == "ret" || m == "retq") close_export(n)
}

END {
  if (in_export) close_export(0)
  for (i = 1; i <= nb; i++) {
    if (!(branches[i] in defined)) bad("branch or call to " branches[i] " outside the unit")
  }
  for (i = 1; i <= no; i++) {
    base = label_base(outside[i])
    if (base in closed) bad("branch into " closed[base] " from outside it (" outside_line[i] ")")
  }
}
