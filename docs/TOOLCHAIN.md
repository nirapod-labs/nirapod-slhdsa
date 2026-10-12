# Toolchain

The implementation is compiled, analysed and proved with one pinned
toolchain, rebuilt from its pinned inputs by `toolchain/build.sh`:

| Component | Pin | Where |
|---|---|---|
| Jasmin compiler and analysers | jasmin-lang/jasmin `2bf326d583659c1fbd0e5b90f7c09fe0c0456e35` plus a patch series | `toolchain/jasmin/PIN`, `toolchain/jasmin/SERIES`, `toolchain/jasmin/PATCHES.md` |
| Rocq environment of the compiler proofs | Rocq 9.0.1, mathcomp 2.4.0, coq-elpi 2.5.2, Hierarchy Builder 1.9.1, coqword `86ed49aeca65`, OCaml 4.14.4 | `toolchain/jasmin/PIN` |
| opam package universe | ocaml/opam-repository `f8293643f2af`, rocq-prover/opam `564ab90f5874` | `toolchain/jasmin/PIN` |
| EasyCrypt | easycrypt/easycrypt `e7eff05dcef1` (main, after r2026.09), Why3 1.8.2 | `toolchain/easycrypt/PIN` |
| SMT provers | Z3 4.8.17, 4.12.6, 4.13.4, 4.16.0; CVC5 1.0.9, 1.2.1; Alt-Ergo 2.5.4, 2.6.4 | `toolchain/easycrypt/PIN` |

One compiler build serves both targets: `-arch x86-64` and `-arch armv8a`.

## Building it

Supported build hosts: Linux on x86-64 and macOS on AArch64, and Linux on
AArch64 for the compiler alone (below). The build needs opam 2.6.0, git,
curl, a C and C++ compiler, GNU make, m4, pkg-config, and the development
files of GMP, MPFR and PPL; EasyCrypt also needs unzip (for the prover
archives) and the development files of PCRE2 and zlib. On Linux, opam
sandboxes package builds with bubblewrap. On Ubuntu:

```sh
apt-get install build-essential git curl m4 pkg-config bubblewrap \
  libgmp-dev libmpfr-dev libppl-dev \
  unzip libpcre2-dev zlib1g-dev    # EasyCrypt
```

On macOS, Xcode command-line tools and, from Homebrew, `gmp mpfr ppl
pkgconf`, and `pcre2` for EasyCrypt.

From a clean checkout, at the repository root:

```sh
JOBS=4 toolchain/build.sh          # switch, jasmin, test
export PATH="$PWD/toolchain/work/bin:$PATH"
eval "$(opam env --root="$PWD/toolchain/work/opam" --switch=nirapod-slhdsa)"
```

`toolchain/build.sh switch|jasmin|test` runs one step. The opam root is
`toolchain/work/opam` unless `OPAMROOT` names another one; other `OPAM*`
settings of the caller are ignored, and the switch is never made the default.
The build needs opam 2.6.0 exactly. With the default root, everything the
build produces is under `toolchain/work/`. The build also points `HOME`,
the `XDG_*` directories and `TMPDIR` there, so no tool reads a
configuration of the user's own, and it checks that every configuration
file EasyCrypt reports, and Why3's, belongs to the switch. One build runs
in a work directory at a time. The comments at the top of
`toolchain/build.sh` say what each step checks and records.

Linux on AArch64 builds the compiler only, because several of the pinned
SMT provers publish no binaries for it:

```sh
JOBS=4 toolchain/build.sh --no-easycrypt
```

This leaves out EasyCrypt, Why3 and the provers, and with them the
`unzip`, PCRE2 and zlib requirements and the check of the Jasmin EasyCrypt
library. The Rocq proofs, the extraction, the assumption and admit checks
and the compiler tests run as in a full build; `provenance.txt` and
`switch.txt` record the reduced set of components. On a platform without
pinned provers, the build stops unless `--no-easycrypt` is given. The mode
has been run on Linux on x86-64; on Linux on AArch64 it has not been run
yet.

## What the build establishes

`toolchain/work/logs/` holds the record of a build:

- `provenance.txt`: date, host, project commit, Jasmin pin, the commit and
  tree ids of the Jasmin tree (the pin with the series of
  `toolchain/jasmin/SERIES`), the series with the SHA-256 of every patch,
  whether the proofs were built from scratch or incrementally,
  compiler and tool versions, and every opam package and pin.
- `proofs.log`: the machine check of the complete Rocq development of the
  tree (`make -C proofs all`).
- `cil.sha256`: the extracted OCaml of the compiler. Every build removes
  the generated files and extracts them again from the checked proofs
  (`make -C compiler CIL`); the hashes are taken right after extraction and
  must be unchanged once the compiler is built.
- `assumptions.log`: `Print Assumptions` for the end-to-end compiler theorem
  `it_compile_prog_to_asmP` and the architecture records `armv8a_h_params`
  and `x86_h_params`. The build stops unless the names printed for each are
  exactly those of `toolchain/jasmin/ASSUMPTIONS`.
- `admit-scan.log`: the `Admitted.`, `admit.` and `Abort.` lines and the
  `Axiom`, `Parameter`, `Hypothesis` and `Conjecture` declarations of the
  proof tree. It is a text scan, which makes any new such line a reviewed
  change; `Print Assumptions` above is what states the assumptions of the
  theorems. The build stops unless the list is exactly
  `toolchain/jasmin/ADMITS`, which explains each kind of entry.
- `eclib-axioms.log`: every `axiom`, `admit` and `admitted` in the Jasmin
  EasyCrypt library. The build stops unless the list is exactly
  `toolchain/jasmin/ECLIB_AXIOMS`.
- `test.log` and `test-suites.txt`: the compiler's test suites, built and
  run again in an emptied directory, and the test executables that ran.
- `eclib.log`: the check of the Jasmin EasyCrypt library. If it fails, it
  runs once more with one job (`eclib-retry.log`), since an SMT call can
  miss its time limit on a loaded host; both logs are kept, and
  `provenance.txt` says whether the retry was used.
- `binaries.sha256` (recorded, not compared: the binaries depend on the
  host), `switch.txt` and `easycrypt-config.txt`.

## Assurance boundary of the toolchain

The Rocq development of Jasmin proves the compiler correct from the source
language to the assembly abstract syntax, for the architecture descriptions as
written in Rocq: if an execution of the source program does not fail, the
generated assembly program has the same observable behaviour. The theorem rests
on the assumptions printed in `assumptions.log`. `make -C proofs all` checks it
again for the tree that is built, so it covers the lowerings and
assembly-generation changes of the patch series (`toolchain/jasmin/PATCHES.md`
gives the status of each patch).

For the pinned tree and series, `assumptions.log` lists, for the end-to-end theorem:
the axioms of Rocq's primitive 63-bit integers (`Uint63Axioms`,
`Sint63Axioms`), proof irrelevance and `Eqdep.Eq_rect_eq.eq_rect_eq`, and the
encoding of code labels as machine words, declared as parameters `encode_label` and
`decode_label` with the axiom `decode_encode_label` (`proofs/arch/label.v`).
The ARMv8-A record rests on the same integer axioms, `eq_rect_eq` and the two
label parameters; the x86-64 record also on the AES helpers `MixColumns` and
`InvMixColumns`, declared without definition. No proof in the tree is
`Admitted`. The other `Axiom` declarations, in `gen_map.v` and
`unionfind.v`, are parameters of module types.

Trusted, not proved:

- the semantics of each instruction as written in Rocq, transcribed from the
  architecture manuals, including the instructions the series adds;
- the EasyCrypt models of the instructions in the Jasmin EasyCrypt library
  (`eclib/JModel_armv8a.ec`, `eclib/JModel_x86.ec`), which `jasmin2ec`
  output refers to, including the `LDRW` model the series adds, and the
  global axioms of that library: its memory model (`JMemory`), the AES
  helpers (`AES`) and the horizontal addition of the x86-64 model
  (`JModel_x86`), listed in `toolchain/jasmin/ECLIB_AXIOMS`;
- the speculative guarantees of barrier instructions, an assumption of the
  speculative constant-time model rather than part of the sequential
  semantics;
- the hand-written OCaml: parser and type checker, the register and stack
  allocation heuristics (their results are checked by proved validators),
  the assembly printers including the Mach-O relocation syntax, the safety
  checker `jasmin-checksafety`, the constant-time checker `jasmin-ct`, and
  `jasmin2ec`;
- OCaml, Rocq, opam, the C compiler, the assembler and the linker;
- for EasyCrypt proofs: EasyCrypt, Why3 and the SMT provers.

A verdict of `jasmin-checksafety` or `jasmin-ct` is evidence from a trusted
analyser, not a proof. The compiler proofs say nothing about the
correctness, safety or constant-time behaviour of a particular Jasmin program.

## Using the compiler

- `jasminc` chooses the default `-system` from the host it was built on.
  Pass `-system linux` (ELF) or `-system macosx` (Mach-O) explicitly whenever
  generated assembly is kept or compared.
- ARMv8-A has no 8- or 16-bit registers: a byte or halfword is loaded into a
  32- or 64-bit register by a zero- or sign-extending load, and a 32-bit word
  is zero-extended to 64 bits by the load itself (`(64u)[:u32 p]`).
- A memory access can only be a whole instruction argument. Write
  `t = (64u) d[0]; x += t;` rather than `x += (64u) d[0];` (the compiler
  reports the latter as an error).
- On ARMv8-A, a constant stored to memory is first moved to a register by the
  compiler, once per store.
- On ARMv8-A, an address has a base register and either an offset register
  or an immediate offset, not both: a stack array indexed by a register is
  addressable only when the array is at offset 0 of the frame; otherwise the
  index must be added to a pointer first.

## EasyCrypt

EasyCrypt reads a project's `easycrypt.project`, where provers are named with
a minimum version (`provers = Z3@4.12`); it uses the lowest installed version
that is at least the one named. The installed set reproduces the choice
EasyCrypt's own CI makes for the developments this project builds on. The
switch has its own Why3 configuration
(`$(opam var lib)/easycrypt/why3.conf`, generated by `build.sh switch`).
Why3 looks for provers on `PATH`; the switch step limits that search to
the switch's own binaries, so a prover the host provides (a distribution
`z3`, for example) is not picked up. It then stops unless the provers
EasyCrypt knows are exactly the pinned versions, each a binary of the
switch.
Why3 1.8.2 does not list Z3 4.16.0 among its known versions and
configures it with the driver of the newest Z3 it knows. CVC5 1.3.4 is not
installed: Why3 1.8.2 cannot read its version.

`easycrypt compile` checks the proofs of the file it is given, not those of
the theories it requires, which it may load from cached `.eco` files. A
complete proof check compiles every file itself; a cached `.eco` file is no
evidence that the proofs of its theory were checked.
