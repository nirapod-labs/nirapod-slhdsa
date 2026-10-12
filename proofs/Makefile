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
#   make scan-admits      fail if any checked file contains a proof hole or
#                         a command that skips checking (admit, admitted,
#                         pragma, exit, fail)
#   make check-constants  re-derive the FIPS 180-4 constant tables and compare
#   make list-axioms      print every axiom the checked files declare
#
# Each file is compiled on its own with -no-eco. EasyCrypt does not re-check
# the proofs of a theory it loads through `require` (unless -check-all,
# which also re-checks its standard library), and a cached .eco would hide a
# stale result; compiling every file separately is what makes a passing run
# mean that every proof in the tree was checked by this run.
#
# Variables: EASYCRYPT (the binary of the pinned toolchain), EC_PROVERS and
# EC_TIMEOUT (this project's theories), IMPORTED_PROVERS and
# IMPORTED_TIMEOUT (the imported crypto-specs theories), PYTHON (the
# scans).

EASYCRYPT  ?= easycrypt
PYTHON     ?= python3

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

IMPORTED_FILES := $(shell find $(CRYPTO_SPECS) \( -name '*.ec' -o -name '*.eca' \) \
                    2>/dev/null | LC_ALL=C sort)

.PHONY: check check-spec check-own check-imported scan-admits check-constants list-axioms

check: scan-admits check-constants check-imported check-own

check-spec: scan-admits check-constants
	@$(MAKE) --no-print-directory LABEL=check-spec FILES="$(SPEC_FILES)" FLAGS="$(OWN_FLAGS)" compile-files

check-own:
	@$(MAKE) --no-print-directory LABEL=check-own FILES="$(OWN_FILES)" FLAGS="$(OWN_FLAGS)" compile-files

check-imported:
	@$(MAKE) --no-print-directory LABEL=check-imported FILES="$(IMPORTED_FILES)" FLAGS="$(IMPORTED_FLAGS)" compile-files

# The hole scan reads code only (tools/scan_holes.py strips comments), so a hole
# that upstream left commented out is not counted, and any hole in code is.
scan-admits:
	@$(PYTHON) -I tools/scan_holes.py $(OWN_FILES) $(IMPORTED_FILES) \
	  && echo "scan-admits: PASS" \
	  || { echo "scan-admits: FAIL"; exit 1; }

check-constants:
	@$(PYTHON) -I tools/sha2_constants.py spec/hash/FIPS180_SHA2.ec

list-axioms:
	@grep -nE '^[[:space:]]*(declare[[:space:]]+)?axiom' $(OWN_FILES) $(IMPORTED_FILES) || true

.PHONY: compile-files
compile-files:
	@test -n "$(LABEL)" || { echo "compile-files: LABEL not set"; exit 1; }
	@test -n "$(FILES)" || { echo "$(LABEL): no files"; exit 1; }
	@n=0; for f in $(FILES); do \
	  printf 'check %s\n' "$$f"; \
	  $(EASYCRYPT) compile $(FLAGS) "$$f" || { echo "FAIL $$f"; exit 1; }; \
	  n=$$((n+1)); \
	done; echo "$(LABEL): PASS $$n files"
