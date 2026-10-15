# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# Makefile
# ========
#
# Single entry point of the build. It compiles the parameter-set units with
# the Jasmin compiler, assembles them with the C wrapper into two static
# libraries, and builds and runs the core tests:
#
#     make            build/<target>/lib/libnirapod_slhdsa.a
#                     build/<target>/lib/libnirapod_slhdsa_testing.a
#     make check      check the symbols of the application library, run the
#                     ACVP known answers, the core, negative, stack, register
#                     and fault tests on this host; writes
#                     build/<target>/transcript-core.txt
#     make fill-check build the library once more with the safety-checker
#                     fills of the core written as 0xa5 bytes instead of
#                     zeros, and run the ACVP known answers and the core
#                     tests on it (tests/core/fill-check.py)
#     make fill-check-controls
#                     one build per fill site, made to depend on the fill
#                     value there; each must fail the known answers
#     make checker-repro
#                     run JASMIN_CHECKSAFETY, which must be the checker of
#                     the pinned toolchain, on the reproducers of the
#                     safety-checker workarounds (tests/core/checker/)
#     make asm        only the Jasmin assembly
#     make gen        write the assembly of every target and its manifest
#                     into gen/ (this tree does not carry gen/)
#     make gen-check  regenerate into build/gen-check and fail on any byte
#                     difference from an existing gen/, MANIFEST included
#                     except the line naming the host's jasminc binary
#     make clean      remove build/
#
# <target> is <arch>-<format>: aarch64-macho, aarch64-elf or x86_64-elf,
# detected from the host for the library and the tests. `make gen` builds
# the assembly of all three, which needs no target hardware.
#
# Tools: JASMINC (and JASMIN_CT for analysis targets) must be the Jasmin
# build that toolchain/build.sh makes from the pins under toolchain/; CC
# must accept C99. JASMINC is required: when it is unset, make looks for
# the assembly in gen/<target>/, which a clean checkout of this tree does
# not have.
#
# Other areas add targets through their own fragments, included at the
# end: <dir>/<name>.mk and <dir>/<sub>/<name>.mk.

# `make` with no target builds the libraries. The goal is named here, ahead
# of every rule, because the first explicit target in the file would
# otherwise become the default.
.DEFAULT_GOAL := all

JASMINC  ?=
JASMIN_CT ?= jasmin-ct
CC       ?= cc
AR       ?= ar

# Source roots. Every source path below goes through one of these.
JASMIN_SRC  ?= src
HASH_SRC    ?= $(JASMIN_SRC)/hash
CAPI_SRC    ?= capi
INCLUDE_DIR ?= include
TESTS_DIR   ?= tests
BUILD       ?= build

# --------------------------------------------------------------------
# Target detection
# --------------------------------------------------------------------

HOST_MACHINE := $(shell uname -m)
HOST_SYSTEM  := $(shell uname -s)

# GEN_ARCH and GEN_SYSTEM replace the host's values only inside `make gen`
# and `make kernel-roots`.
MACHINE := $(if $(GEN_ARCH),$(GEN_ARCH),$(HOST_MACHINE))
SYSTEM  := $(if $(GEN_SYSTEM),$(GEN_SYSTEM),$(HOST_SYSTEM))

ifneq ($(filter arm64 aarch64,$(MACHINE)),)
ARCH        := aarch64
JASMIN_ARCH := armv8a
else ifeq ($(MACHINE),x86_64)
ARCH        := x86_64
JASMIN_ARCH := x86-64
else
$(error unsupported machine $(MACHINE))
endif

ifeq ($(SYSTEM),Darwin)
FORMAT        := macho
JASMIN_SYSTEM := macosx
else ifeq ($(SYSTEM),Linux)
FORMAT        := elf
JASMIN_SYSTEM := linux
else
$(error unsupported system $(SYSTEM))
endif

TARGET := $(ARCH)-$(FORMAT)
OUT    := $(BUILD)/$(TARGET)

# --------------------------------------------------------------------
# Jasmin units
# --------------------------------------------------------------------

SETS := sha2_128s shake_128s sha2_128f shake_128f \
        sha2_192s shake_192s sha2_192f shake_192f \
        sha2_256s shake_256s sha2_256f shake_256f

# Hash variants (src/hash/README.md; capi/sets.c). scalar is built
# for every set and runs on every CPU of the architecture. Each set also
# has an accelerated variant, selected at run time on CPUs with the
# extensions it needs (capi/dispatch.c):
#
#     x86-64   avx2    SHAKE sets: the four-way Keccak kernel in AVX2
#              shani   SHA2 sets: the SHA-256 kernel on the SHA extensions
#     AArch64  sha3    SHAKE sets: single-way and four-way Keccak on the
#                      SHA-3 instructions (FEAT_SHA3)
#              sha2    SHA2 sets: SHA-256 and SHA-512 on the SHA-2
#                      instructions (FEAT_SHA256, FEAT_SHA512)
SHAKE_SETS := $(filter shake_%,$(SETS))
SHA2_SETS  := $(filter sha2_%,$(SETS))

UNITS := $(addsuffix -scalar,$(SETS))
ifeq ($(ARCH),x86_64)
UNITS += $(addsuffix -avx2,$(SHAKE_SETS)) $(addsuffix -shani,$(SHA2_SETS))
else
UNITS += $(addsuffix -sha3,$(SHAKE_SETS)) $(addsuffix -sha2,$(SHA2_SETS))
endif

# Kernel roots. A rule that compiles or analyses unit <set>-<variant> has
# the unit as its stem ($*), and JASMIN_INCLUDES below takes the kernels of
# that variant from here: the scalar default of each root, unless the
# variant names a replacement as K1_<variant>, KX_<variant> or
# S1_<variant>. This is the one place a variant's kernels are named, so
# every rule that builds or checks a unit sees the kernels the library
# ships. On AArch64 the scalar single-way Keccak is the one that keeps the
# state in registers. SHA-2 stays on the portable kernels in the scalar
# variant on both architectures: their compression functions are the ones
# proven against FIPS 180-4 (proofs/README.md), and the A64 kernels in
# sha2/aarch64/scalar are tested but not yet proven.
ifeq ($(ARCH),aarch64)
SCALAR_K1 = $(HASH_SRC)/keccak/aarch64/scalar
else
SCALAR_K1 = $(HASH_SRC)/keccak
endif
KX_avx2  = $(HASH_SRC)/keccak/x86_64/avx2
S1_shani = $(HASH_SRC)/sha2/x86_64/shani
# The sha3 variant takes both kernels of keccak/aarch64/sha3, single-way
# and four-way.
K1_sha3  = $(HASH_SRC)/keccak/aarch64/sha3
KX_sha3  = $(HASH_SRC)/keccak/aarch64/sha3
S1_sha2  = $(HASH_SRC)/sha2/aarch64/sha2
UNIT_VARIANT = $(lastword $(subst -, ,$*))
VARIANT_K1 = $(or $(K1_$(UNIT_VARIANT)),$(SCALAR_K1))
VARIANT_KX = $(or $(KX_$(UNIT_VARIANT)),$(HASH_SRC)/keccak)
VARIANT_S1 = $(or $(S1_$(UNIT_VARIANT)),$(HASH_SRC)/sha2)

# Fault hooks (src/slhdsa/hook/hook.jinc): the identity for every
# library unit; only the fault test units below use another version.
VARIANT_HOOK = $(JASMIN_SRC)/slhdsa/hook

# Include roots: the FIPS 205 modules, and the hash layer with its
# per-architecture word helpers and the kernels of the chosen variant
# (src/hash/README.md).
JASMIN_INCLUDES = -I Slhdsa=$(JASMIN_SRC)/slhdsa \
                  -I Hash=$(HASH_SRC) \
                  -I HashWord=$(HASH_SRC)/$(ARCH) \
                  -I KeccakKernel=$(VARIANT_K1) \
                  -I KeccakKernelX=$(VARIANT_KX) \
                  -I Sha2Kernel=$(VARIANT_S1) \
                  -I Sha2KernelX=$(HASH_SRC)/sha2 \
                  -I SlhdsaHook=$(VARIANT_HOOK)

# -stack-zero: each export clears the stack it used before returning
# (docs/API.md records what this covers and how it is checked).
JASMIN_FLAGS = -arch $(JASMIN_ARCH) -system $(JASMIN_SYSTEM) \
               -stack-zero loop -stack-zero-size u64 -nowarning

JASMIN_DEPS := $(sort $(shell find $(JASMIN_SRC) $(HASH_SRC) -name '*.jinc'))

ASM   := $(addprefix $(OUT)/asm/,$(addsuffix .s,$(UNITS)))
JOBJ  := $(addprefix $(OUT)/obj/,$(addsuffix .o,$(UNITS)))

# The compilation unit of <set>-<variant> wraps sets/<set>.jinc in the
# namespace that names its symbols (capi/jasmin.h).
$(OUT)/units/%.jazz:
	@mkdir -p $(@D)
	@set=$$(echo $* | sed 's/-.*//'); variant=$$(echo $* | sed 's/.*-//'); \
	printf 'namespace nirapod_slhdsa_jz_%s_%s {\n  from Slhdsa require "sets/%s.jinc"\n}\n' \
	  $$set $$variant $$set > $@

$(OUT)/asm/%.s: $(OUT)/units/%.jazz $(JASMIN_DEPS)
	@mkdir -p $(@D)
	@test -n "$(JASMINC)" || { echo "JASMINC is not set: needed to compile $<" >&2; exit 1; }
	$(JASMINC) $(JASMIN_FLAGS) $(JASMIN_INCLUDES) -o $@ $<
	@echo "$(JASMIN_FLAGS) $(JASMIN_INCLUDES)" > $(@:.s=.flags)

# The assembly the objects come from: compiled here when JASMINC is set,
# else gen/<target>/ as `make gen` writes it (absent from this tree).
GEN_DIR ?= gen
ifeq ($(strip $(JASMINC)),)
ASM_DIR := $(GEN_DIR)/$(TARGET)
$(GEN_DIR)/$(TARGET)/%.s:
	@echo "$@ is missing: set JASMINC to the pinned jasminc to compile the Jasmin sources" >&2; exit 1
else
ASM_DIR := $(OUT)/asm
endif

# The Linux assemblers accept the mnemonics of the AArch64 crypto-extension
# kernels only with those extensions enabled (+sha2: FEAT_SHA256; +sha3:
# FEAT_SHA512 and FEAT_SHA3). The option only widens what the assembler
# accepts: the instructions are those of the .s file.
UNIT_ASFLAGS := $(if $(filter aarch64-elf,$(TARGET)),-march=armv8.2-a+sha2+sha3)

$(OUT)/obj/%.o: $(ASM_DIR)/%.s
	@mkdir -p $(@D)
	$(CC) $(UNIT_ASFLAGS) -c -o $@ $<

# --------------------------------------------------------------------
# C wrapper and libraries
# --------------------------------------------------------------------
#
# Every C file is compiled twice (capi/internal.h, "Two builds"):
#
#     obj/c/          production objects
#     obj/c-testing/  the same sources with NIRAPOD_SLHDSA_TESTING, which
#                     adds the FIPS 205 internal functions, caller-chosen
#                     seeds and opt_rand, and the fault-check switch, plus
#                     capi/testing/testing.c
#
# Libraries:
#
#     libnirapod_slhdsa.a          the production objects and the Jasmin
#                                  units, linked into one relocatable object
#                                  in which only the functions of
#                                  include/nirapod_slhdsa.h stay global; every
#                                  other symbol, Jasmin exports included, is
#                                  made local (ld -r with an exported-symbols
#                                  list on Mach-O; ld -r, then objcopy
#                                  --keep-global-symbols on ELF)
#     libnirapod_slhdsa_testing.a  the testing objects and the same Jasmin
#                                  units, every symbol as compiled; for tests
#                                  only, and the only library they link
#
# `make check` runs tests/abi/check-exports.sh on the first, with a
# negative control (one extra global symbol) that must fail.

CFLAGS ?= -O2
CWARN  := -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wmissing-prototypes \
          -Wstrict-prototypes -Wpointer-arith -Werror
CPPFLAGS += -I$(INCLUDE_DIR) -I$(CAPI_SRC) -I$(CAPI_SRC)/testing
TESTING_DEF := -DNIRAPOD_SLHDSA_TESTING

LD      ?= ld
OBJCOPY ?= objcopy

CAPI_FILES := api clear dispatch entropy sets timing
CAPI_DEPS  := $(wildcard $(CAPI_SRC)/*.h) $(INCLUDE_DIR)/nirapod_slhdsa.h
COBJ       := $(addprefix $(OUT)/obj/c/,$(addsuffix .o,$(CAPI_FILES)))
TCOBJ      := $(addprefix $(OUT)/obj/c-testing/,$(addsuffix .o,$(CAPI_FILES) testing))

$(OUT)/obj/c/%.o: $(CAPI_SRC)/%.c $(CAPI_DEPS)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CWARN) $(CFLAGS) -c -o $@ $<

$(OUT)/obj/c-testing/%.o: $(CAPI_SRC)/%.c $(CAPI_DEPS)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(TESTING_DEF) $(CWARN) $(CFLAGS) -c -o $@ $<

$(OUT)/obj/c-testing/testing.o: $(CAPI_SRC)/testing/testing.c $(CAPI_DEPS) \
                                $(CAPI_SRC)/testing/nirapod_slhdsa_testing.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(TESTING_DEF) $(CWARN) $(CFLAGS) -c -o $@ $<

LIB         := $(OUT)/lib/libnirapod_slhdsa.a
TESTING_LIB := $(OUT)/lib/libnirapod_slhdsa_testing.a

# The symbols that stay global: the header's functions, with the Mach-O
# prefix where the format has one.
SYM_PREFIX  := $(if $(filter macho,$(FORMAT)),_,)
EXPORTS     := $(OUT)/lib/exports.txt
CHECK_EXPORTS := sh $(TESTS_DIR)/abi/check-exports.sh

$(EXPORTS): $(INCLUDE_DIR)/nirapod_slhdsa.h $(TESTS_DIR)/abi/check-exports.sh
	@mkdir -p $(@D)
	$(CHECK_EXPORTS) list $< $(SYM_PREFIX) > $@

LIB_OBJ := $(OUT)/obj/libnirapod_slhdsa.o

# The link recipe is in this Makefile: a change to it relinks the object.
ifeq ($(FORMAT),macho)
$(LIB_OBJ): $(COBJ) $(JOBJ) $(EXPORTS) Makefile
	$(LD) -r -o $@ $(COBJ) $(JOBJ) -exported_symbols_list $(EXPORTS)
else
$(LIB_OBJ): $(COBJ) $(JOBJ) $(EXPORTS) Makefile
	$(LD) -r -o $@.all $(COBJ) $(JOBJ)
	$(OBJCOPY) --keep-global-symbols=$(EXPORTS) $@.all $@
	rm -f $@.all
endif

$(LIB): $(LIB_OBJ)
	@mkdir -p $(@D)
	rm -f $@
	$(AR) rcs $@ $^

$(TESTING_LIB): $(TCOBJ) $(JOBJ)
	@mkdir -p $(@D)
	rm -f $@
	$(AR) rcs $@ $^

# Negative control of the symbol check: the production object plus one
# object defining one more global function.
EXPORTS_CONTROL := $(OUT)/lib/exports-control.a

$(EXPORTS_CONTROL): $(LIB_OBJ)
	@mkdir -p $(OUT)/obj/exports-control
	printf 'int nirapod_slhdsa_extra(void);\nint nirapod_slhdsa_extra(void) { return 0; }\n' \
	  > $(OUT)/obj/exports-control/extra.c
	$(CC) -c -o $(OUT)/obj/exports-control/extra.o $(OUT)/obj/exports-control/extra.c
	rm -f $@
	$(AR) rcs $@ $(LIB_OBJ) $(OUT)/obj/exports-control/extra.o

# --------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------

# Every test links the testing library alone, except those that link the
# application library alone: test_production (key generation, hedged and
# deterministic signing and verification for every set),
# test_acvp_production (the known answers below run once on each library),
# test_stack_production (the secret scan and the stack depth of the public
# functions; test_stack_base the same with the scalar variant selected for
# every set, see tests/abi/dispatch_base.c) and test_entropy (the operating system's random source made to
# fail).

CORE_TESTS := $(OUT)/tests/test_core $(OUT)/tests/test_negative \
              $(OUT)/tests/test_stack $(OUT)/tests/test_registers \
              $(OUT)/tests/test_acvp $(OUT)/tests/test_acvp_production \
              $(OUT)/tests/test_production $(OUT)/tests/test_stack_production \
              $(OUT)/tests/test_stack_base \
              $(OUT)/tests/test_entropy

PRODUCTION_TEST_CC = $(CC) -I$(INCLUDE_DIR) $(CWARN) $(CFLAGS)

TEST_CC = $(CC) $(CPPFLAGS) $(TESTING_DEF) $(CWARN) $(CFLAGS)

$(OUT)/tests/test_core: $(TESTS_DIR)/core/test_core.c $(TESTING_LIB)
	@mkdir -p $(@D)
	$(TEST_CC) -o $@ $< $(TESTING_LIB)

$(OUT)/tests/test_negative: $(TESTS_DIR)/negative/test_negative.c $(TESTING_LIB)
	@mkdir -p $(@D)
	$(TEST_CC) -o $@ $< $(TESTING_LIB)

# Known answers from the NIST ACVP vectors (tests/core/acvp-subset.txt).
ACVP_SUBSET := $(TESTS_DIR)/core/acvp-subset.txt

$(OUT)/tests/test_acvp: $(TESTS_DIR)/core/test_acvp.c $(TESTING_LIB)
	@mkdir -p $(@D)
	$(TEST_CC) -o $@ $< $(TESTING_LIB)

$(OUT)/tests/test_acvp_production: $(TESTS_DIR)/core/test_acvp.c $(LIB)
	@mkdir -p $(@D)
	$(PRODUCTION_TEST_CC) -DNIRAPOD_SLHDSA_ACVP_PRODUCTION -o $@ $< $(LIB)

# Negative control of the known-answer test (tests/core/acvp-control.sh).
ACVP_CONTROL := $(TESTS_DIR)/core/acvp-control.sh

$(OUT)/tests/test_production: $(TESTS_DIR)/core/test_production.c $(LIB)
	@mkdir -p $(@D)
	$(PRODUCTION_TEST_CC) -o $@ $< $(LIB)

# The application library's C objects with dispatch.o replaced, and its
# units, linked directly: the code is that of the library, so the depths
# are those of the public functions on a CPU without the extensions.
BASE_COBJ := $(filter-out $(OUT)/obj/c/dispatch.o,$(COBJ)) $(OUT)/obj/c-base/dispatch_base.o

$(OUT)/obj/c-base/dispatch_base.o: $(TESTS_DIR)/abi/dispatch_base.c $(CAPI_SRC)/dispatch.c $(CAPI_DEPS)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CWARN) $(CFLAGS) -c -o $@ $<

$(OUT)/tests/test_stack_base: $(TESTS_DIR)/abi/test_stack.c $(BASE_COBJ) $(JOBJ)
	@mkdir -p $(@D)
	$(PRODUCTION_TEST_CC) -DNIRAPOD_SLHDSA_STACK_PRODUCTION -DNIRAPOD_SLHDSA_STACK_BASE \
	  -o $@ $< $(BASE_COBJ) $(JOBJ)

$(OUT)/tests/test_stack_production: $(TESTS_DIR)/abi/test_stack.c $(LIB)
	@mkdir -p $(@D)
	$(PRODUCTION_TEST_CC) -DNIRAPOD_SLHDSA_STACK_PRODUCTION -o $@ $< $(LIB)

# test_entropy defines the random-source function the library calls, so it
# must link the library as an archive (tests/negative/test_entropy.c).
$(OUT)/tests/test_entropy: $(TESTS_DIR)/negative/test_entropy.c $(LIB)
	@mkdir -p $(@D)
	$(PRODUCTION_TEST_CC) -o $@ $< $(LIB)

# Stack depth and residue of the exports (tests/abi/test_stack.c), and its
# negative control: two units compiled without stack zeroization, which
# must leave residue for the probe to be trusted.

CONTROL_SETS := sha2_128f shake_128f
CONTROL_OBJ  := $(addprefix $(OUT)/control/,$(addsuffix -scalar.o,$(CONTROL_SETS)))
JASMIN_FLAGS_NOZERO = -arch $(JASMIN_ARCH) -system $(JASMIN_SYSTEM) -nowarning

$(OUT)/control/%.s: $(OUT)/units/%.jazz $(JASMIN_DEPS)
	@mkdir -p $(@D)
	$(JASMINC) $(JASMIN_FLAGS_NOZERO) $(JASMIN_INCLUDES) -o $@ $<

$(OUT)/control/%.o: $(OUT)/control/%.s
	$(CC) -c -o $@ $<

$(OUT)/tests/test_stack: $(TESTS_DIR)/abi/test_stack.c $(TESTING_LIB)
	@mkdir -p $(@D)
	$(TEST_CC) -o $@ $< $(TESTING_LIB)

# Register state after the library returns (tests/abi/test_registers.c).
$(OUT)/tests/test_registers: $(TESTS_DIR)/abi/test_registers.c $(TESTING_LIB)
	@mkdir -p $(@D)
	$(TEST_CC) -o $@ $< $(TESTING_LIB)

$(OUT)/tests/test_stack_control: $(TESTS_DIR)/abi/test_stack.c $(CONTROL_OBJ)
	@mkdir -p $(@D)
	$(TEST_CC) -DNIRAPOD_SLHDSA_STACK_CONTROL -o $@ $< $(CONTROL_OBJ)

# The fault check of the C layer (tests/negative/test_fault.c): units whose
# hooks flip a bit of the FORS public key (faultfors) or of the layer-0
# XMSS root (faultht) during signing.

FAULT_SETS := sha2_128f shake_128f
FAULT_OBJ  := $(foreach s,$(FAULT_SETS),$(OUT)/fault/$(s)-faultfors.o $(OUT)/fault/$(s)-faultht.o)
FAULT_DEPS := $(wildcard $(TESTS_DIR)/negative/fault/*/hook.jinc)

$(OUT)/fault/%-faultfors.s: VARIANT_HOOK = $(TESTS_DIR)/negative/fault/fors
$(OUT)/fault/%-faultht.s:   VARIANT_HOOK = $(TESTS_DIR)/negative/fault/ht

$(OUT)/fault/%.s: $(OUT)/units/%.jazz $(JASMIN_DEPS) $(FAULT_DEPS)
	@mkdir -p $(@D)
	@test -n "$(JASMINC)" || { echo "JASMINC is not set: needed to compile $<" >&2; exit 1; }
	$(JASMINC) $(JASMIN_FLAGS) $(JASMIN_INCLUDES) -o $@ $<

$(OUT)/fault/%.o: $(OUT)/fault/%.s
	$(CC) -c -o $@ $<

$(OUT)/tests/test_fault: $(TESTS_DIR)/negative/test_fault.c $(FAULT_OBJ) $(TESTING_LIB)
	@mkdir -p $(@D)
	$(TEST_CC) -o $@ $< $(FAULT_OBJ) $(TESTING_LIB)

# The safety-checker limitations the core works around, reproduced on
# small exports (tests/core/checker/).

PYTHON   ?= python3
JASMIN_CHECKSAFETY ?=

.PHONY: checker-repro

# The expected verdicts are those of the pinned checker, so no checker is
# taken from the PATH by default.
checker-repro:
	@test -n "$(JASMIN_CHECKSAFETY)" || { echo "make checker-repro needs JASMIN_CHECKSAFETY," \
	  "the jasmin-checksafety that toolchain/build.sh builds from the pin" >&2; exit 1; }
	$(PYTHON) -I $(TESTS_DIR)/core/checker/check.py $(JASMIN_CHECKSAFETY)

# The fill check (tests/core/fill-check.py): the same library from a copy
# of the Jasmin sources whose fills hold 0xa5 bytes, in its own build
# directory, with the known answers and the core tests run on it; and its
# controls, one build per fill site.

FILL_DIR := $(BUILD)/fill-check
FILL_JOBS ?= 1

.PHONY: fill-check fill-check-run fill-check-controls

fill-check:
	@test -n "$(JASMINC)" || { echo "make fill-check needs JASMINC" >&2; exit 1; }
	$(PYTHON) -I $(TESTS_DIR)/core/fill-check.py prepare $(JASMIN_SRC) $(FILL_DIR)/src
	$(MAKE) --no-print-directory BUILD=$(FILL_DIR)/build JASMIN_SRC=$(FILL_DIR)/src fill-check-run

fill-check-run: $(OUT)/tests/test_acvp $(OUT)/tests/test_core
	$(OUT)/tests/test_acvp $(ACVP_SUBSET)
	$(OUT)/tests/test_core $(TEST_CORE_FLAGS)

fill-check-controls:
	@test -n "$(JASMINC)" || { echo "make fill-check-controls needs JASMINC" >&2; exit 1; }
	FILL_JOBS=$(FILL_JOBS) $(PYTHON) -I $(TESTS_DIR)/core/fill-check.py controls $(JASMIN_SRC) $(BUILD)/fill-controls \
	  $(TARGET) $(abspath $(ACVP_SUBSET))

# --------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------

.PHONY: all asm lib check clean

all: lib

asm: $(ASM)

lib: $(LIB) $(TESTING_LIB)

# TEST_CORE_FLAGS: e.g. --require-variants on a host that must run every
# compiled variant (tests/core/test_core.c).
TEST_CORE_FLAGS ?=

ifeq ($(strip $(JASMINC)),)
CHECK_TESTS := $(CORE_TESTS)
else
CHECK_TESTS := $(CORE_TESTS) $(OUT)/tests/test_stack_control $(OUT)/tests/test_fault
endif

check: $(CHECK_TESTS) $(LIB) $(EXPORTS_CONTROL)
	$(CHECK_EXPORTS) check $(INCLUDE_DIR)/nirapod_slhdsa.h $(LIB) $(SYM_PREFIX)
	@if $(CHECK_EXPORTS) check $(INCLUDE_DIR)/nirapod_slhdsa.h $(EXPORTS_CONTROL) $(SYM_PREFIX) \
	    > $(OUT)/exports-control.log; then \
	  echo "check-exports: the negative control was accepted" >&2; exit 1; fi
	@echo "check-exports: negative control rejected ($$(head -n 1 $(OUT)/exports-control.log))"
	$(OUT)/tests/test_production
	$(OUT)/tests/test_acvp_production $(ACVP_SUBSET)
	$(ACVP_CONTROL) $(OUT)/tests/test_acvp_production $(ACVP_SUBSET) $(OUT)/acvp-control
	$(OUT)/tests/test_acvp $(ACVP_SUBSET)
	$(OUT)/tests/test_negative
	$(OUT)/tests/test_core $(TEST_CORE_FLAGS) --transcript $(OUT)/transcript-core.txt
	$(OUT)/tests/test_stack
	$(OUT)/tests/test_stack_production
	$(OUT)/tests/test_stack_base
	$(OUT)/tests/test_registers
	$(OUT)/tests/test_entropy
ifeq ($(strip $(JASMINC)),)
	@echo "test_stack (negative control): NOT RUN (needs JASMINC)"
	@echo "test_fault: NOT RUN (needs JASMINC)"
else
	$(OUT)/tests/test_stack_control --expect-residue
	$(OUT)/tests/test_fault
endif

# --------------------------------------------------------------------
# Generated assembly (gen/)
# --------------------------------------------------------------------
#
# gen/<target>/<set>-<variant>.s is the output of JASMINC for that unit
# with the flags above, and gen/MANIFEST identifies how it was made: the
# Jasmin commit and the digests of toolchain/jasmin/PIN and SERIES (when
# present), the digest of the jasminc binary with the host system it ran
# on, the flags of each unit, a digest of every Jasmin source, and the
# digest of every generated file. Apart from the binary line nothing in it
# depends on the host, the time or the path, so regeneration with the same
# toolchain and sources is byte-identical.

GEN_TARGETS := aarch64-macho aarch64-elf x86_64-elf
SHA256      := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256")

.PHONY: gen gen-check gen-target

# One target's assembly into $(GEN_INTO)/$(TARGET), and the compiler
# arguments of each unit into $(GEN_INTO).units (internal; run by gen).
gen-target: $(ASM)
	@mkdir -p $(GEN_INTO)/$(TARGET)
	cp $(ASM) $(GEN_INTO)/$(TARGET)/
	@for u in $(UNITS); do echo "unit $(TARGET)/$$u $$(cat $(OUT)/asm/$$u.flags)"; done >> $(GEN_INTO).units

# gen_into(dir): regenerate every target into dir and write dir/MANIFEST.
define gen_into
	@test -n "$(JASMINC)" || { echo "make gen needs JASMINC" >&2; exit 1; }
	rm -rf $(1) $(1).units $(BUILD)/gen-build
	@for t in $(GEN_TARGETS); do \
	  $(MAKE) --no-print-directory gen-target GEN_INTO=$(abspath $(1)) BUILD=$(BUILD)/gen-build \
	    GEN_ARCH=$$(echo $$t | cut -d- -f1) \
	    GEN_SYSTEM=$$(echo $$t | sed 's/.*-macho$$/Darwin/; s/.*-elf$$/Linux/') || exit 1; \
	done
	@{ echo "# gen/MANIFEST: written by make gen; do not edit"; \
	   echo "# The -version line of jasminc is a placeholder in this build; the"; \
	   echo "# compiler is identified by the pin, the patch series and the binary."; \
	   echo "compiler-version $$($(JASMINC) -version 2>&1 | head -n 1)"; \
	   if [ -f toolchain/jasmin/PIN ]; then \
	     echo "jasmin-commit $$(sed -n 's/^JASMIN_COMMIT=//p' toolchain/jasmin/PIN)"; \
	   else echo "jasmin-commit unknown (toolchain/jasmin/PIN absent)"; fi; \
	   for f in PIN SERIES; do \
	     if [ -f toolchain/jasmin/$$f ]; then echo "toolchain/jasmin/$$f $$($(SHA256) toolchain/jasmin/$$f | cut -d' ' -f1)"; \
	     else echo "toolchain/jasmin/$$f absent"; fi; \
	   done; \
	   echo "jasminc-binary $$($(SHA256) $$(command -v $(JASMINC)) | cut -d' ' -f1) $$(uname -s)-$$(uname -m)"; \
	   echo "sources $$(find $(JASMIN_SRC) -name '*.jinc' | LC_ALL=C sort | xargs $(SHA256) | $(SHA256) | cut -d' ' -f1)"; \
	   LC_ALL=C sort $(1).units; \
	   cd $(1) && find . -name '*.s' | LC_ALL=C sort | sed 's|^\./||' | xargs $(SHA256); \
	 } > $(1)/MANIFEST.tmp
	mv $(1)/MANIFEST.tmp $(1)/MANIFEST
	rm -f $(1).units
endef

gen:
	$(call gen_into,$(GEN_DIR))

# The include roots each unit of the target is compiled with, one line per
# unit: <arch> <unit> -I <root>=<dir> ... (JASMIN_INCLUDES). Needs no
# toolchain. ci/kernel_roots.py runs it for each target and checks that
# the proof models are extracted under the kernels the library builds.
.PHONY: kernel-roots
kernel-roots: $(addprefix kernel-roots/,$(UNITS))

kernel-roots/%:
	@echo "$(ARCH) $* $(JASMIN_INCLUDES)"

# The jasminc-binary line names the binary of the host that generated, which
# differs between hosts (and operating systems) for the same compiler
# source; gen-check compares every other byte and reports that line.
gen-check:
	@test -d $(GEN_DIR) || { echo "gen-check: $(GEN_DIR)/ is absent" >&2; exit 1; }
	$(call gen_into,$(BUILD)/gen-check)
	diff -r -x MANIFEST $(GEN_DIR) $(BUILD)/gen-check
	grep -v '^jasminc-binary ' $(GEN_DIR)/MANIFEST > $(BUILD)/gen-check.manifest.committed
	grep -v '^jasminc-binary ' $(BUILD)/gen-check/MANIFEST > $(BUILD)/gen-check.manifest.regenerated
	diff $(BUILD)/gen-check.manifest.committed $(BUILD)/gen-check.manifest.regenerated
	@echo "gen-check: every generated file and MANIFEST line is byte-identical to $(GEN_DIR)/"
	@echo "gen-check: committed   $$(grep '^jasminc-binary ' $(GEN_DIR)/MANIFEST)"
	@echo "gen-check: regenerated $$(grep '^jasminc-binary ' $(BUILD)/gen-check/MANIFEST)"

clean:
	rm -rf $(BUILD)

.SECONDARY:

# ci/ holds the recipes of the CI checks (ci/checks/*.mk, ci/mk/common.mk),
# which are not fragments of this build.
-include $(sort $(filter-out ci/%,$(wildcard */*.mk */*/*.mk)))
