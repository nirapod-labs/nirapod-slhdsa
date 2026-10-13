# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# proofs/Makefile
#
# Machine-checks the EasyCrypt development. Every target fails closed: a
# file that does not check, a prover that is missing, a timeout, a proof
# hole or a command that skips checking (tools/scan_holes.py) stops the run
# with a non-zero status.
#
#   make check            the proof-hole scan, the constant check, then every
#                         EasyCrypt file here and in the imported theories
#   make check-own        proofs/spec, without the scans
#   make check-spec       the scans, then proofs/spec only
#   make check-imported   the imported crypto-specs theories, re-checked here
#   make check-correctness the correctness proofs, once per extracted model
#   make check-pair PAIR=<arch>/<variant>   one model only
#   make scan-admits      fail if any checked file contains a proof hole or
#                         a command that skips checking (admit, admitted,
#                         pragma, exit, fail)
#   make check-constants  re-derive the FIPS 180-4 constant tables and compare
#   make check-inventory  fail unless EasyCrypt's list of the axioms in scope
#                         and the claimed theorem statements equal the
#                         committed inventory/<arch>-<variant>.txt
#   make inventory        rewrite the inventory files
#   make extract          regenerate extracted/<arch>/<variant>/ with jasmin2ec
#   make check-extraction re-extract into a scratch directory and fail if the
#                         committed models differ or a model directory is
#                         not in EXTRACTIONS (stale-model check)
#
# Each file is compiled on its own with -no-eco. EasyCrypt does not re-check
# the proofs of a theory it loads through `require` (unless -check-all,
# which also re-checks its standard library), and a cached .eco would hide a
# stale result; compiling every file separately is what makes a passing run
# mean that every proof in the tree was checked by this run.
#
# Variables: EASYCRYPT (the binary of the pinned toolchain), EC_PROVERS and
# EC_TIMEOUT (this project's theories), IMPORTED_PROVERS and
# IMPORTED_TIMEOUT (the imported crypto-specs theories), JASMIN2EC and
# JASMIN_SRC (the pinned jasmin2ec and the root of the Jasmin sources, for
# extraction), PYTHON (the scans).

EASYCRYPT  ?= easycrypt
JASMIN2EC  ?= jasmin2ec
PYTHON     ?= python3
JASMIN_SRC ?= ../src

CRYPTO_SPECS := ../third_party/crypto-specs

EC_PATH := -R spec \
           -R $(CRYPTO_SPECS)/common -R $(CRYPTO_SPECS)/fips202 \
           -I JazzEC:$(CRYPTO_SPECS)/arrays

# Provers and SMT timeout (seconds). Prover names carry a minimum version;
# EasyCrypt runs the lowest installed version that satisfies it, so with the
# provers of the EasyCrypt pin these select fixed binaries. The imported
# theories keep the selection of their upstream project file.
EC_PROVERS       ?= -p Z3@4.16
EC_TIMEOUT       ?= 10
IMPORTED_PROVERS ?= -p CVC5@1.2 -p Z3@4.8
IMPORTED_TIMEOUT ?= 30

OWN_FLAGS      := -no-eco $(EC_PATH) $(EC_PROVERS) -timeout $(EC_TIMEOUT)
IMPORTED_FLAGS := -no-eco $(EC_PATH) $(IMPORTED_PROVERS) -timeout $(IMPORTED_TIMEOUT)

OWN_FILES      := $(shell find spec \
                    \( -name '*.ec' -o -name '*.eca' \) 2>/dev/null | LC_ALL=C sort)
SPEC_FILES     := $(filter spec/%,$(OWN_FILES))

# ------------------------------------------------------------------
# Correctness proofs, checked once per extracted model
#
# Layout and naming (one convention for every proof of extracted code):
#
#   extracted/<arch>/<variant>/       the model: HashExtracted (+ arrays)
#   correctness/<area>/...            shared proofs, any directory whose
#                                     path has no architecture component;
#                                     checked against every pair
#   correctness/<area>/<arch>/        facts about one architecture's
#                                     instructions (theory ArchWord), for
#                                     every variant of that architecture
#   correctness/<area>/<arch>/<variant>/  proofs of the kernels a variant
#                                     replaces (theory KernelSpec), for
#                                     that pair only
#
# A pair is checked with its model, its architecture and variant
# directories and every shared directory on the load path, so a shared
# proof that requires HashExtracted, ArchWord or KernelSpec is checked
# against that pair's versions. Theory names must be unique on that path.
ARCHS := x86_64 aarch64
PAIRS = $(foreach e,$(EXTRACTIONS),$(firstword $(subst :, ,$(e))))

archpat := $(foreach a,$(ARCHS),-e '/$(a)/' -e '/$(a)$$')
SHARED_PROOF_DIRS = $(shell find correctness -type d 2>/dev/null | grep -v $(archpat) | LC_ALL=C sort)
SHARED_PROOFS     = $(shell for d in $(SHARED_PROOF_DIRS); do \
                      find $$d -maxdepth 1 \( -name '*.ec' -o -name '*.eca' \); done | LC_ALL=C sort)
pair_arch    = $(firstword $(subst /, ,$(1)))
pair_dirs    = $(foreach d,$(SHARED_PROOF_DIRS),$(wildcard $(d)/$(call pair_arch,$(1)) $(d)/$(1)))
pair_files   = $(sort $(wildcard extracted/$(1)/*.ec) \
                 $(foreach d,$(call pair_dirs,$(1)),$(wildcard $(d)/*.ec $(d)/*.eca)) \
                 $(SHARED_PROOFS))
pair_flags   = -no-eco $(EC_PATH) -I extracted/$(1) \
               $(foreach d,$(SHARED_PROOF_DIRS) $(call pair_dirs,$(1)),-I $(d)) \
               $(EC_PROVERS) -timeout $(EC_TIMEOUT)
IMPORTED_FILES := $(shell find $(CRYPTO_SPECS) \( -name '*.ec' -o -name '*.eca' \) \
                    2>/dev/null | LC_ALL=C sort)

.PHONY: check check-spec check-own check-imported check-correctness scan-admits check-constants

check: scan-admits check-constants check-imported check-own check-correctness

check-spec: scan-admits check-constants
	@$(MAKE) --no-print-directory LABEL=check-spec FILES="$(SPEC_FILES)" FLAGS="$(OWN_FLAGS)" compile-files

check-own:
	@$(MAKE) --no-print-directory LABEL=check-own FILES="$(OWN_FILES)" FLAGS="$(OWN_FLAGS)" compile-files

check-imported:
	@$(MAKE) --no-print-directory LABEL=check-imported FILES="$(IMPORTED_FILES)" FLAGS="$(IMPORTED_FLAGS)" compile-files

check-correctness:
	@for p in $(PAIRS); do \
	  echo "pair $$p"; \
	  $(MAKE) --no-print-directory PAIR=$$p check-pair || exit 1; \
	done

.PHONY: check-pair
check-pair:
	@test -n "$(PAIR)" || { echo "check-pair: PAIR not set"; exit 1; }
	@$(MAKE) --no-print-directory LABEL="check-pair $(PAIR)" FILES="$(call pair_files,$(PAIR))" \
	  FLAGS="$(call pair_flags,$(PAIR))" compile-files

# The hole scan reads code only (tools/scan_holes.py strips comments), so a hole
# that upstream left commented out is not counted, and any hole in code is.
scan-admits:
	@$(PYTHON) -I tools/scan_holes.py $(OWN_FILES) $(IMPORTED_FILES) \
	  $(shell find correctness extracted \( -name '*.ec' -o -name '*.eca' \) 2>/dev/null) \
	  && echo "scan-admits: PASS" \
	  || { echo "scan-admits: FAIL"; exit 1; }

check-constants:
	@$(PYTHON) -I tools/sha2_constants.py spec/hash/FIPS180_SHA2.ec

# ------------------------------------------------------------------
# Axiom and theorem inventory
#
# For each pair, tools/inventory.py requires every theory checked for that
# pair and records what EasyCrypt prints for `print axiom` (every axiom in
# scope, whether declared, given by `axiomatized by`, or left unrealized by
# a clone) and the statements of THEOREMS. check-inventory fails on any
# difference from the committed file, and on an inventory file of a pair
# that is no longer extracted.

THEOREMS := \
  SHA256_Compress.sha256_rounds_correct SHA256_Compress.sha256_compress_correct \
  SHA256_Compress.sha256_compress_total \
  SHA512_Compress.sha512_rounds_correct SHA512_Compress.sha512_compress_correct \
  SHA512_Compress.sha512_compress_total

inventory_file = inventory/$(subst /,-,$(1)).txt

.PHONY: inventory check-inventory inventory-pair
inventory:
	@mkdir -p inventory
	@for p in $(PAIRS); do \
	  $(MAKE) --no-print-directory PAIR=$$p MODE=write inventory-pair || exit 1; \
	done

check-inventory:
	@for p in $(PAIRS); do \
	  $(MAKE) --no-print-directory PAIR=$$p MODE=check inventory-pair || exit 1; \
	done
	@expected="$(foreach p,$(PAIRS),$(call inventory_file,$(p)))"; \
	for f in inventory/*; do \
	  case " $$expected " in *" $$f "*) ;; \
	    *) echo "check-inventory: FAIL ($$f is not the inventory of a pair in EXTRACTIONS)"; exit 1;; \
	  esac; \
	done; echo "check-inventory: PASS"

inventory-pair:
	@test -n "$(PAIR)" || { echo "inventory-pair: PAIR not set"; exit 1; }
	@$(PYTHON) -I tools/inventory.py --pair $(PAIR) --easycrypt "$(EASYCRYPT)" \
	  --flags "$(call pair_flags,$(PAIR))" --namespace JazzEC=$(CRYPTO_SPECS)/arrays \
	  --theorems "$(THEOREMS)" --$(MODE) $(call inventory_file,$(PAIR)) \
	  $(OWN_FILES) $(IMPORTED_FILES) $(call pair_files,$(PAIR))

# ------------------------------------------------------------------
# Extraction
#
# Each (architecture, variant) pair is one extraction of extracted/hash.jazz
# into extracted/<arch>/<variant>/, under the include roots that select its
# kernels. The theory of the extracted program is always HashExtracted, so
# the correctness proofs, which require it by that name, are checked once
# per pair against that pair's model. tools/extract.sh adds the generated-
# file headers.

HASH_SRC := $(JASMIN_SRC)/hash

# <arch>/<variant>:<jasmin arch>:<KeccakKernel>:<KeccakKernelX>:<Sha2Kernel>:<Sha2KernelX>
EXTRACTIONS := \
  x86_64/scalar:x86-64:keccak:keccak:sha2:sha2 \
  aarch64/scalar:armv8a:keccak:keccak:sha2:sha2

.PHONY: extract check-extraction
extract:
	@for e in $(EXTRACTIONS); do \
	  JASMIN2EC="$(JASMIN2EC)" HASH_SRC="$(HASH_SRC)" sh tools/extract.sh "$$e" extracted || exit 1; \
	done

check-extraction:
	@tmp=$$(mktemp -d) || exit 1; \
	for e in $(EXTRACTIONS); do \
	  JASMIN2EC="$(JASMIN2EC)" HASH_SRC="$(HASH_SRC)" sh tools/extract.sh "$$e" "$$tmp" || { rm -rf "$$tmp"; exit 1; }; \
	  d=$${e%%:*}; \
	  diff -r "$$tmp/$$d" "extracted/$$d" > /dev/null \
	    || { echo "check-extraction: FAIL ($$d differs from a fresh extraction)"; rm -rf "$$tmp"; exit 1; }; \
	done; rm -rf "$$tmp"; \
	expected="$(foreach e,$(EXTRACTIONS),extracted/$(firstword $(subst :, ,$(e))))"; \
	for d in extracted/*/*; do \
	  case " $$expected " in *" $$d "*) ;; \
	    *) echo "check-extraction: FAIL ($$d is not a pair in EXTRACTIONS)"; exit 1;; \
	  esac; \
	done; echo "check-extraction: PASS"

.PHONY: compile-files
# Each file is checked from a scratch copy that ends with a trivial lemma.
# EasyCrypt accepts a file that ends while obligations of a `clone ...
# proof *` are still unrealized, and then treats them as proven; any
# command after them is rejected ("cannot process [axiom] inside a proof
# script"). The sentinel lemma makes such a file fail.
compile-files:
	@test -n "$(LABEL)" || { echo "compile-files: LABEL not set"; exit 1; }
	@test -n "$(FILES)" || { echo "$(LABEL): no files"; exit 1; }
	@n=0; for f in $(FILES); do \
	  printf 'check %s\n' "$$f"; \
	  tmp=$$(mktemp -d) || exit 1; \
	  cp "$$f" "$$tmp/" && \
	  printf '\n(* gate: end of file *)\nlemma end_of_file_gate : true by trivial.\n' >> "$$tmp/$$(basename "$$f")"; \
	  $(EASYCRYPT) compile $(FLAGS) -I "$$(dirname "$$f")" "$$tmp/$$(basename "$$f")" \
	    || { echo "FAIL $$f"; rm -rf "$$tmp"; exit 1; }; \
	  rm -rf "$$tmp"; n=$$((n+1)); \
	done; echo "$(LABEL): PASS $$n files"
