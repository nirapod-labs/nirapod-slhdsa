#!/bin/sh
# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# analysis/asm/check-controls.sh
# ==============================
#
# Negative controls of check-asm.sh. Each control is a file with a single
# violation of one rule, named as a real unit so that no other rule has
# anything to object to. Every control must be rejected, and with the
# message of its own rule: a rule that stops firing fails here even while
# the other rules still reject their controls.
#
# usage: check-controls.sh <arch: aarch64|x86_64> <dir>
# Writes each control to <dir>/<name>/sha2_128f-scalar.s and check-asm.sh's
# output for it to <dir>/<name>.log; exit status 0 when every control is
# rejected by its rule.

arch=$1
dir=$2
here=$(dirname "$0")
fail=0
n=0

# control NAME MESSAGE LINE: a control holding LINE (backslash escapes
# expanded), which check-asm.sh must reject with a line ending in MESSAGE
# (an extended regular expression).
control() {
  mkdir -p "$dir/$1"
  f=$dir/$1/sha2_128f-scalar.s
  printf '%b\n' "$3" > "$f"
  if sh "$here/check-asm.sh" "$arch" "$f" > "$dir/$1.log" 2>&1; then
    echo "control $1: accepted"
    fail=1
  elif ! grep -Eq ": $2\$" "$dir/$1.log"; then
    echo "control $1: rejected, but not by its rule ($2)"
    fail=1
  fi
  n=$((n + 1))
}

# mutant NAME MESSAGE SED: a control made from the export of $template
# (one export that passes every rule, written to the file with its
# escapes expanded) by the sed script SED, which check-asm.sh must reject
# with MESSAGE. The template itself must be accepted, or a rule that
# rejects every export would pass its controls.
mutant() {
  mkdir -p "$dir/$1"
  f=$dir/$1/sha2_128f-scalar.s
  printf '%b\n' "$template" | sed "$3" > "$f"
  if sh "$here/check-asm.sh" "$arch" "$f" > "$dir/$1.log" 2>&1; then
    echo "control $1: accepted"
    fail=1
  elif ! grep -Eq ": $2\$" "$dir/$1.log"; then
    echo "control $1: rejected, but not by its rule ($2)"
    fail=1
  fi
  n=$((n + 1))
}

accept_template() {
  mkdir -p "$dir/template"
  printf '%b\n' "$template" > "$dir/template/sha2_128f-scalar.s"
  if ! sh "$here/check-asm.sh" "$arch" "$dir/template/sha2_128f-scalar.s" > "$dir/template.log" 2>&1; then
    echo "control template: a passing export rejected ($(head -n 1 "$dir/template.log"))"
    fail=1
  fi
}

# stops NAME SCRIPT: the template, checked with an awk that exits 2 once
# it has run SCRIPT over the file, as an awk that stops partway leaves it:
# no message for the lines it did not reach. check-asm.sh must fail the
# file with "SCRIPT failed"; other scripts run on the real awk.
stops() {
  mkdir -p "$dir/$1"
  printf '#!/bin/sh\n"%s" "$@" || exit\ncase " $* " in *"/%s "*) exit 2 ;; esac\n' \
    "$(command -v awk)" "$2" > "$dir/$1/awk"
  chmod +x "$dir/$1/awk"
  f=$dir/$1/sha2_128f-scalar.s
  printf '%b\n' "$template" > "$f"
  if PATH="$dir/$1:$PATH" sh "$here/check-asm.sh" "$arch" "$f" > "$dir/$1.log" 2>&1; then
    echo "control $1: accepted"
    fail=1
  elif ! grep -Eq ": $2 failed\$" "$dir/$1.log"; then
    echo "control $1: rejected, but not as a failed $2"
    fail=1
  fi
  n=$((n + 1))
}

symbol='global symbol [A-Za-z0-9_]+ outside the export set'
leave='keygen does not clear its stack before returning'
out='keygen branches out of the export \(.*\)'
fence='keygen has no speculation barrier before its first call'
late='keygen branches past its return \(.*\)'
after='keygen has code after its return \(.*\)'
into='branch into keygen from outside it \(.*\)'
trap='trap or system-register instruction \(.*\)'
indirect='indirect branch or call \(.*\)'
data='data directive in a code section \(.*\)'
control globl  "$symbol" '\t.globl\tnirapod_slhdsa_jz_sha2_128f_scalar__other'
control global "$symbol" '\t.global\tnirapod_slhdsa_jz_sha2_128f_scalar__other'
control weak   "$symbol" '\t.weak\tnirapod_slhdsa_jz_sha2_128f_scalar__other'

case $arch in
  aarch64)
    control udiv 'division instruction' '\tudiv\tx1, x2, x3'
    control sdiv 'division instruction' '\tsdiv\tw1, w2, w3'
    control x18  'uses x18' '\tmov\tx18, x1'
    control w18  'uses x18' '\tldr\tw18, [sp]'
    control x29  'uses x29' '\tmov\tx29, x1'
    control w29  'uses x29' '\tmov\tw29, w1'
    control fp   'uses x29' '\tstp\tfp, lr, [sp, #-16]!'
    control svc  "$trap" '\tsvc\t#0x80'
    # An instruction written as data: MSR DIT, #0 as its encoding.
    control inst "$data" '\t.inst\t0xd503415f'
    control msr  "$trap" '\tmsr\ts3_3_c4_c2_5, x1'
    control mrs  "$trap" '\tmrs\tx1, s3_3_c4_c2_5'
    control blr  "$indirect" '\tblr\tx3'
    control br   "$indirect" '\tbr\tx3'
    # Timing: an instruction Arm does not list as data-independent-time
    # (FMUL), a listed mnemonic in a form that is not (LDR literal), a
    # branch form outside the accepted ones, a MOVK on a non-constant.
    dit='instruction outside the data-independent-time list \(.*\)'
    movk='movk on a register that does not hold a constant \(.*\)'
    control fmul    "$dit"  '\tfmul\td0, d1, d2'
    control literal "$dit"  '\tldr\tx1, Lc\nLc:\n\t.quad\t1'
    control retreg  "$dit"  '\tret\tx3'
    control movk    "$movk" '\tmov\tx1, x2\n\tmovk\tx1, #1, lsl #16'
    e=Lnirapod_slhdsa_jz_sha2_128f_scalar__keygen
    template="_nirapod_slhdsa_jz_sha2_128f_scalar__keygen:
\tstr\tx30, [sp, #-16]!\n\tdsb\tsy\n\tisb\n\tbl\tLf\$1
\tmovz\tx4, #1\n\tmovk\tx4, #2, lsl #16\n\tmovk\tx4, #3, lsl #32
\tmov\tx2, sp\n\tmovz\tx3, #64\n\tand\tx12, x2, #18446744073709551600
\tmov\tsp, x12\n\tsub\tsp, sp, x3\n\tmov\tx12, #0\n$e\$2:
\tsubs\tx3, x3, #8\n\tstr\tx12, [sp, x3]\n\tb.ne\t$e\$2
\tmov\tsp, x2\n\tldr\tx30, [sp], #16\n\tret\nLf\$1:\n\tret
\t.section\t__TEXT, __const\nG\$c:\n\t.byte\t1, 2"
    accept_template
    mutant leave-ret   "$leave" '/^.mov.x2, sp$/,/^.ldr.x30/d'
    mutant leave-value "$leave" 's/mov.x12, #0$/mov	x12, #1/'
    mutant leave-size  "$leave" 's/movz.x3, #64$/movz	x3, #60/'
    mutant leave-out   "$out"   's/^.mov.x2, sp$/	b	Lf$1\
&/'
    # A second way out: an early branch to a label of the export placed
    # after its RET, which returns without zeroing; such a label alone;
    # a jump into the export from the code after it. The first also has
    # a label after the RET; its control is the branch.
    mutant leave-late  "$late"  's/^.bl.Lf.1$/&\
	b.eq	'"$e"'$9/
s/^Lf.1:$/'"$e"'$9:\
	ldr	x30, [sp], #16\
	ret\
&/'
    mutant leave-after "$after" 's/^Lf.1:$/'"$e"'$9:\
	ret\
&/'
    mutant leave-into  "$into"  's/^Lf.1:$/&\
	b	'"$e"'$2/'
    mutant fence       "$fence" '/^.dsb/d'
    mutant extcall     'branch or call to _memcpy outside the unit' 's/bl.Lf.1$/bl	_memcpy/'
    mutant movk-chain  "$movk" '/^.movz.x4/d'
    mutant movk-label  "$movk" 's/^.movk.x4, #3/Lk:\
&/'
    stops awk-dit     dit.awk
    stops awk-exports exports.awk
    ;;
  x86_64)
    control divq  'division instruction' '\tdivq\t%rcx'
    control idivl 'division instruction' '\tidivl\t%ecx'
    control div   'division instruction' '\tdiv\t%rcx'
    control syscall "$trap" '\tsyscall'
    control hlt     "$trap" '\thlt'
    control callr   "$indirect" '\tcallq\t*%rax'
    control jmpr    "$indirect" '\tjmp\t*%rax'
    # An instruction written as data: SYSCALL as its encoding.
    control byte    "$data" '\t.text\n\t.byte\t0x0f, 0x05'
    e=.Lnirapod_slhdsa_jz_sha2_128f_scalar__keygen
    template="nirapod_slhdsa_jz_sha2_128f_scalar__keygen:
\tmovq\t%rsp, %rax\n\tlfence\n\tcall\t.Lf\$1
\tmovq\t%rsp, %rsi\n\tandq\t\$-16, %rsp\n\tsubq\t\$64, %rsp\n\tmovq\t\$64, %rdi\n$e\$2:
\tsubq\t\$8, %rdi\n\tmovq\t\$0, (%rsp,%rdi)\n\tjne\t$e\$2
\tmovq\t%rsi, %rsp\n\tret\n.Lf\$1:\n\tret
\t.section\t.rodata, \"a\", %progbits\nG\$c:\n\t.byte\t1, 2"
    accept_template
    mutant leave-ret   "$leave" '/^.movq.%rsp, %rsi$/,/^.movq.%rsi, %rsp$/d'
    mutant leave-value "$leave" 's/movq.\$0, (%rsp,%rdi)$/movq	$1, (%rsp,%rdi)/'
    mutant leave-size  "$leave" 's/movq.\$64, %rdi$/movq	$56, %rdi/'
    mutant leave-out   "$out"   's/^.movq.%rsp, %rsi$/	jmp	.Lf$1\
&/'
    mutant leave-late  "$late"  's/^.call.\.Lf.1$/&\
	je	'"$e"'$9/
s/^\.Lf.1:$/'"$e"'$9:\
	ret\
&/'
    mutant leave-after "$after" 's/^\.Lf.1:$/'"$e"'$9:\
	ret\
&/'
    mutant leave-into  "$into"  's/^\.Lf.1:$/&\
	jmp	'"$e"'$2/'
    mutant fence       "$fence" '/^.lfence/d'
    mutant extcall     'branch or call to memcpy outside the unit' 's/call.\.Lf.1$/call	memcpy/'
    stops awk-exports exports.awk
    ;;
  *)
    echo "check-controls.sh: unknown architecture $arch" >&2
    exit 2
    ;;
esac

if [ "$fail" -eq 0 ]; then echo "check-controls.sh: $n controls, each rejected by its rule"; fi
exit $fail
