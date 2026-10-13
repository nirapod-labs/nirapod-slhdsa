# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# Hash primitive tests: build the test exports with jasminc, link them into
# the C harness, and run CAVP, Monte Carlo and differential tests.
#
# Run from the repository root or from this directory:
#
#   make -C tests/hash vectors           fetch and verify the NIST CAVP files
#   make -C tests/hash check             build and run every test natively
#   make -C tests/hash ct sct            jasmin-ct on every test export
#   make -C tests/hash constants         recompute constant tables
#   make -C tests/hash generated         regenerate generated test sources, fail if stale
#   make -C tests/hash negative-control  show the tests detect a wrong constant
#   make -C tests/hash fill-check        run the tests with 0xa5-filled one-shot buffers
#
# Cross-host x86-64 flow (jasminc is only needed where the assembly is made):
#
#   make -C tests/hash asm negative-control-asm fill-check-asm ARCH=x86_64 SYSTEM=linux
#                                                                    any host with jasminc
#   make -C tests/hash check-prebuilt negative-control-prebuilt fill-check-prebuilt
#                                                                    x86-64 host
#
# The variant variables below must be the same in both steps.
# Variables:
#
#   JASMINC, JASMIN_CT  Jasmin tools (default: from PATH)
#   ARCH                x86_64 | aarch64 (default: this machine)
#   SYSTEM              linux | macosx (default: this machine)
#   KECCAK_VARIANT      single-way Keccak kernel directory under src/hash/keccak
#   KECCAKX_VARIANT     4-way Keccak kernel directory, same tree
#   SHA2_VARIANT        single-way SHA-2 kernel directory under src/hash/sha2
#   SHA2X_VARIANT       multi-way SHA-2 kernel directory, same tree
#                       (each empty: the shared scalar kernels)
#   VECTORS             extracted CAVP directory (default: build/hash/vectors)
#   DIFF_SEED, DIFF_ITERS   differential test seed and iteration count

ROOT     := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
HASH     := $(ROOT)/src/hash
TESTS    := $(ROOT)/tests/hash

JASMINC    ?= jasminc
JASMIN_CT  ?= jasmin-ct
CC         ?= cc
PYTHON     ?= python3

UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)
ARCH    ?= $(if $(filter arm64 aarch64,$(UNAME_M)),aarch64,x86_64)
SYSTEM  ?= $(if $(filter Darwin,$(UNAME_S)),macosx,linux)

JARCH_aarch64 := armv8a
JARCH_x86_64  := x86-64
JARCH := $(JARCH_$(ARCH))

KECCAK_VARIANT  ?=
KECCAKX_VARIANT ?=
SHA2_VARIANT    ?=
SHA2X_VARIANT   ?=
tag = $(if $(1),$(subst /,_,$(1)),scalar)
KECCAK_TAG  := keccak_$(call tag,$(KECCAK_VARIANT))-keccakx_$(call tag,$(KECCAKX_VARIANT))
SHA2_TAG    := sha2_$(call tag,$(SHA2_VARIANT))-sha2x_$(call tag,$(SHA2X_VARIANT))
VARIANT_TAG := $(KECCAK_TAG)-$(SHA2_TAG)

# Kernel roots relative to $(HASH)
KECCAK_DIR  := keccak$(if $(KECCAK_VARIANT),/$(KECCAK_VARIANT))
KECCAKX_DIR := keccak$(if $(KECCAKX_VARIANT),/$(KECCAKX_VARIANT))
SHA2_DIR    := sha2$(if $(SHA2_VARIANT),/$(SHA2_VARIANT))
SHA2X_DIR   := sha2$(if $(SHA2X_VARIANT),/$(SHA2X_VARIANT))

JROOTS := -I Hash=$(HASH) \
          -I HashWord=$(HASH)/$(ARCH) \
          -I KeccakKernel=$(HASH)/$(KECCAK_DIR) \
          -I KeccakKernelX=$(HASH)/$(KECCAKX_DIR) \
          -I Sha2Kernel=$(HASH)/$(SHA2_DIR) \
          -I Sha2KernelX=$(HASH)/$(SHA2X_DIR)

BUILD   := $(ROOT)/build/hash
OUT     := $(BUILD)/$(ARCH)-$(SYSTEM)-$(VARIANT_TAG)
ASM     := $(OUT)/hash_test.s
BIN     := $(OUT)/hash_test
VECTORS ?= $(BUILD)/vectors

JSRC := $(wildcard $(TESTS)/jasmin/*.jazz $(TESTS)/jasmin/*.jinc) \
        $(shell find $(HASH) -name '*.jinc')
CSRC := $(TESTS)/c/hash_test.c
CHDR := $(wildcard $(TESTS)/c/*.h)

# libcrypto is the differential oracle; it is linked by soname so that only
# the runtime library is needed, not its development package.
ifeq ($(SYSTEM),macosx)
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
CRYPTO_LIBS ?= -L$(OPENSSL_PREFIX)/lib -lcrypto
else
CRYPTO_LIBS ?= -l:libcrypto.so.3
endif

CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror

DIFF_SEED  ?= 20261012
DIFF_ITERS ?= 2000

.PHONY: all asm check check-prebuilt run vectors ct sct constants generated
.PHONY: negative-control negative-control-asm negative-control-prebuilt clean
.PHONY: fill-check fill-check-asm fill-check-prebuilt

all: check

asm: $(ASM)

$(ASM): $(JSRC)
	@mkdir -p $(OUT)
	$(JASMINC) -arch $(JARCH) -system $(SYSTEM) $(JROOTS) -o $@ $(TESTS)/jasmin/hash_test.jazz

$(BIN): $(ASM) $(CSRC) $(CHDR)
	$(CC) $(CFLAGS) -o $@ $(CSRC) $(ASM) $(CRYPTO_LIBS)

# The run steps are sub-makes, so that under make -j they start only after
# the build they test is complete.
check: $(BIN)
	$(MAKE) --no-print-directory run

# The x86-64 host builds from a copied assembly file without jasminc.
check-prebuilt:
	@test -f $(ASM) || { echo "missing $(ASM): run 'make asm' on a host with jasminc"; exit 1; }
	$(CC) $(CFLAGS) -o $(BIN) $(CSRC) $(ASM) $(CRYPTO_LIBS)
	$(MAKE) --no-print-directory run

run:
	@test -d $(VECTORS) || { echo "missing $(VECTORS): run 'make vectors'"; exit 1; }
	$(BIN) cavp $(VECTORS)
	$(BIN) diff $(DIFF_SEED) $(DIFF_ITERS)

vectors:
	$(TESTS)/vectors/fetch.sh $(VECTORS)

# Constant-time and speculative constant-time type checks of every export
# in the test unit, on the target architecture's analysis model.
ct:
	$(JASMIN_CT) --arch $(JARCH) $(JROOTS) $(TESTS)/jasmin/hash_test.jazz
sct:
	$(JASMIN_CT) --arch $(JARCH) --sct $(JROOTS) $(TESTS)/jasmin/hash_test.jazz

constants:
	$(PYTHON) -I $(TESTS)/tools/check_constants.py $(HASH)

# test_arrays.jinc is generated; regenerate it and fail if the committed
# file differs.
generated:
	$(PYTHON) -I $(TESTS)/tools/gen_test_arrays.py | cmp -s - $(TESTS)/jasmin/test_arrays.jinc || \
	  { echo "tests/hash/jasmin/test_arrays.jinc is stale: regenerate it"; exit 1; }

# Mutates one round constant per kernel family in a copy of the sources and
# requires the tests on that copy to fail in every family below. The
# multi-way families are the checks against libcrypto: the multi-way
# kernels read the same mutated tables as the single-way ones, so
# comparisons between the two cannot detect the mutation.
NEG_FAMILIES := SHA3_256 SHA256Short SHA512Short keccak_x4 sha256_x8 sha512_x4
NEG_WORK     := $(OUT)/negative-control

negative-control-asm:
	JASMINC=$(JASMINC) JARCH=$(JARCH) SYSTEM=$(SYSTEM) ARCH=$(ARCH) \
	KECCAK_DIR=$(KECCAK_DIR) KECCAKX_DIR=$(KECCAKX_DIR) SHA2_DIR=$(SHA2_DIR) SHA2X_DIR=$(SHA2X_DIR) \
	$(TESTS)/tools/negative_control.sh build $(HASH) $(NEG_WORK) $(TESTS)/jasmin/hash_test.jazz

negative-control-prebuilt:
	@test -d $(VECTORS) || { echo "missing $(VECTORS): run 'make vectors'"; exit 1; }
	CC=$(CC) CRYPTO_LIBS="$(CRYPTO_LIBS)" NEG_FAMILIES="$(NEG_FAMILIES)" \
	$(TESTS)/tools/negative_control.sh run $(NEG_WORK) $(CSRC) $(VECTORS)

negative-control: negative-control-asm
	$(MAKE) --no-print-directory negative-control-prebuilt

# Fill check (tools/fill_check.sh): the one-shot buffers are zeroed only for
# the safety checker; a build that fills them with 0xa5 must pass every test.
FILL_WORK := $(OUT)/fill-check

fill-check-asm:
	JASMINC=$(JASMINC) JARCH=$(JARCH) SYSTEM=$(SYSTEM) ARCH=$(ARCH) \
	KECCAK_DIR=$(KECCAK_DIR) KECCAKX_DIR=$(KECCAKX_DIR) SHA2_DIR=$(SHA2_DIR) SHA2X_DIR=$(SHA2X_DIR) \
	$(TESTS)/tools/fill_check.sh build $(HASH) $(TESTS)/jasmin $(FILL_WORK)

fill-check-prebuilt:
	@test -d $(VECTORS) || { echo "missing $(VECTORS): run 'make vectors'"; exit 1; }
	CC=$(CC) CFLAGS="$(CFLAGS)" CRYPTO_LIBS="$(CRYPTO_LIBS)" \
	DIFF_SEED=$(DIFF_SEED) DIFF_ITERS=$(DIFF_ITERS) \
	$(TESTS)/tools/fill_check.sh run $(FILL_WORK) $(CSRC) $(VECTORS)

fill-check: fill-check-asm
	$(MAKE) --no-print-directory fill-check-prebuilt

clean:
	rm -rf $(OUT)
