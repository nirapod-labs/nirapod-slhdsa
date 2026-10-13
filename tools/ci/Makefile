# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/Makefile
# =================
#
# The checks of the continuous integration. Run from the repository root:
#
#     make -f tools/ci/Makefile <target>
#
# Each checking job of the workflows runs one target, so it can be repeated
# on a workstation with the same command:
#
#     ci-source       checks that need no Jasmin toolchain: the component
#                     map, the hash kernel sets, constant tables against
#                     their definitions, generated test sources, the
#                     proof-hole scan
#     ci-vectors      fetch and verify the NIST test vectors (network)
#     ci-vectors-key  the cache key of the ACVP vectors
#     ci-test         build and run every test suite for this host: hash
#                     CAVP, differential and negative control per kernel
#                     set; core, negative, ABI, register and fault tests;
#                     ACVP and its negative controls
#     ci-transcript   the deterministic outputs of the core tests (written
#                     by ci-test), for the cross-platform comparison
#     ci-agree        the transcripts in CI_TRANSCRIPTS (CI_PLATFORMS of
#                     them) are byte-identical
#     ci-analysis     jasmin-ct and jasmin-ct --sct on every unit and kernel
#                     set of this host's architecture; emitted-code policies
#     ci-safety-scope whether this event runs the safety checker
#     ci-safety       jasmin-checksafety (CI_SAFETY=run), or a NOT RUN
#                     statement (CI_SAFETY=defer)
#     ci-diff         differential test of the library against an
#                     independent implementation, and its negative control
#     ci-proofs       the EasyCrypt development and its admit scan, and the
#                     identity of the committed extracted models
#     ci-generated    regenerate gen/ and fail on any byte difference
#
# Besides these targets, the workflows run only the scripts beside this
# file: installing and checking the toolchain, the lint of the repository's
# automation and licensing, and the final check that every job succeeded.
#
# This file is not a fragment of the top-level Makefile (its name keeps it
# out of that Makefile's */*.mk and */*/*.mk includes): CI has to run on
# trees that have no top-level Makefile yet. It calls the top-level
# Makefile and the component Makefiles as sub-makes.
#
# Components
# ----------
#
# Each check belongs to a component of the repository. The table below is
# the one list of component directories; a component is present when any of
# its directories exists. Every directory of the tree is accounted for at
# the levels where components live:
#
#   - each directory at the root is a component directory, a container of
#     component directories (CI_CONTAINERS), or one of the roots that hold
#     no component (CI_OTHER_ROOTS);
#   - each directory directly inside a container is a component directory.
#
# A directory that is none of these fails every target, so a component at a
# path this table does not know cannot pass as absent. When the layout
# changes, this table changes with it.
#
# third_party/crypto-specs and third_party/formosa-slhdsa are checked by
# the proofs (imported theories are re-checked on this copy).
# tests/vectors holds the ACVP pins and their fetch script; the CAVP pins
# of the hash tests live in tests/hash/vectors. If tests/vectors comes to
# hold the pins of another suite, it moves out of the acvp row.
#
# Contract. A check of an absent component prints NOT APPLICABLE, with the
# directories it looked for, and passes; this is the state of a tree into
# which that component has not been merged. A check of a present component
# is mandatory: a missing Makefile, target, tool or input fails it, nothing
# in it is skipped, and its suites must reach their minimum case counts
# (tools/ci/counts.py). In particular:
#
#   - a kernel set whose CPU features the host lacks is an error
#     (tools/ci/cpu-has.sh), and so is a hash kernel variant directory that
#     no kernel set selects;
#   - ACVP and the differential test exercise the library, so either one
#     without the core component is an error;
#   - the component targets this file calls are part of the contract: `ct`
#     (analysis/ct), `safety` (analysis/safety), `asm-policy` (analysis/asm)
#     and `gen-check` (gen/) of the top-level Makefile, the targets of
#     tests/hash, tests/acvp, tests/diff and proofs named below.
#
# Benchmarks (bench/) are a known component that CI does not run: timings
# on shared hosted runners are not evidence.
#
# Toolchain: JASMINC, JASMIN_CT (top-level and tests/hash Makefiles),
# JASMIN2EC and EASYCRYPT (proofs/Makefile), jasmin-checksafety
# (analysis/safety) default to the names on PATH; the workflows put the
# pinned toolchain there.
#
# The top-level Makefile assembles the library from the shipped gen/ when
# JASMINC is empty, and then leaves out the tests that need the compiler.
# CI checks the compiler's own output and runs every test, so each core
# sub-make gets JASMINC explicitly, resolved from PATH; a present core with
# no jasminc on PATH is an error. ci-generated then shows that gen/ is that
# same output, byte for byte.

CI_BUILD   := build
CI_OUT     := $(CI_BUILD)/ci
CI_LOGS    := $(CI_OUT)/logs
CI_PYTHON  ?= python3
CI_COUNTS  := $(CI_PYTHON) -I tools/ci/counts.py

CI_COMPONENTS := hash core acvp diff safety asm proofs gen bench

CI_DIRS_hash   := src/jasmin/hash tests/hash
CI_DIRS_core   := include src/jasmin/slhdsa src/c tests/core tests/negative \
                  tests/abi analysis/ct
CI_DIRS_acvp   := tests/acvp tests/vectors
CI_DIRS_diff   := tests/diff
CI_DIRS_safety := analysis/safety
CI_DIRS_asm    := analysis/asm
CI_DIRS_proofs := proofs third_party/crypto-specs third_party/formosa-slhdsa
CI_DIRS_gen    := gen
CI_DIRS_bench  := bench

CI_CONTAINERS  := src src/jasmin tests analysis third_party
CI_OTHER_ROOTS := .git .github LICENSES docs toolchain tools build

present = $(strip $(foreach d,$(CI_DIRS_$(1)),$(wildcard $(d))))
not_applicable = @echo "$(1): NOT APPLICABLE, the $(2) component is absent (none of: $(CI_DIRS_$(2)))"

CI_HASH   := $(call present,hash)
CI_CORE   := $(call present,core)
CI_ACVP   := $(call present,acvp)
CI_DIFF   := $(call present,diff)
CI_SAFETY_DIRS := $(call present,safety)
CI_ASM    := $(call present,asm)
CI_PROOFS := $(call present,proofs)
CI_GEN    := $(call present,gen)

# subdirs(dirs): the directories directly inside the existing ones of dirs.
# find is given its start points explicitly and never runs without one (GNU
# find would then list the current directory).
subdirs = $(if $(wildcard $(1)),$(shell find $(wildcard $(1)) -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort))

CI_KNOWN_DIRS   := $(foreach c,$(CI_COMPONENTS),$(CI_DIRS_$(c)))
CI_ROOT_DIRS    := $(patsubst ./%,%,$(call subdirs,.))
CI_FOUND_DIRS   := $(call subdirs,$(CI_CONTAINERS))
CI_UNKNOWN_DIRS := $(filter-out $(CI_KNOWN_DIRS) $(CI_CONTAINERS) $(CI_OTHER_ROOTS),$(CI_ROOT_DIRS) $(CI_FOUND_DIRS))

ifneq ($(CI_UNKNOWN_DIRS),)
$(error directories tools/ci/Makefile does not account for: $(CI_UNKNOWN_DIRS); add each to its component, or to CI_OTHER_ROOTS if it holds none)
endif

# Host. The names follow the top-level Makefile: <arch>-<format> is the
# directory of its build, build/<arch>-<format>/.
CI_MACHINE := $(shell uname -m)
CI_SYSTEM  := $(shell uname -s)
CI_ARCH    := $(if $(filter arm64 aarch64,$(CI_MACHINE)),aarch64,$(if $(filter x86_64,$(CI_MACHINE)),x86_64))
CI_FORMAT  := $(if $(filter Darwin,$(CI_SYSTEM)),macho,$(if $(filter Linux,$(CI_SYSTEM)),elf))
ifeq ($(CI_ARCH),)
$(error unsupported machine $(CI_MACHINE))
endif
ifeq ($(CI_FORMAT),)
$(error unsupported system $(CI_SYSTEM))
endif
CI_TARGET := $(CI_ARCH)-$(CI_FORMAT)

# Hash kernel sets
# ----------------
#
# A kernel set is one choice of the four kernel roots of tests/hash/Makefile.
# Each architecture is tested twice: with the portable scalar kernels, and
# with all of its own kernels selected together. Between them, the CAVP and
# differential tests run every kernel the architecture has; ci-source fails
# when a variant directory exists that no set selects, or a set selects one
# that does not exist. CI_HASH_CPU_<set> lists the CPU features the set
# needs on the runner.

CI_HASH_SETS := scalar $(CI_ARCH)

CI_HASH_VARS_scalar  :=
CI_HASH_CPU_scalar   :=
CI_HASH_VARS_x86_64  := KECCAKX_VARIANT=x86_64/avx2 SHA2_VARIANT=x86_64/shani \
                        SHA2X_VARIANT=x86_64/avx2
CI_HASH_CPU_x86_64   := avx2 sha_ni
CI_HASH_VARS_aarch64 := KECCAK_VARIANT=aarch64/scalar
CI_HASH_CPU_aarch64  :=

# <family>/<arch>/<variant> of each assignment: KECCAK* select keccak/,
# SHA2* select sha2/.
ci_selected = $(foreach a,$(1),$(if $(filter KECCAK%,$(a)),keccak,sha2)/$(word 2,$(subst =, ,$(a))))
CI_HASH_SELECTED := $(sort $(call ci_selected,$(CI_HASH_VARS_x86_64) $(CI_HASH_VARS_aarch64)))
CI_HASH_VARIANTS := $(sort $(patsubst src/jasmin/hash/%,%,$(call subdirs,$(call subdirs,$(call subdirs,src/jasmin/hash)))))

# Core variants: test_core runs with --require-variants, so a variant built
# for the architecture that cannot run on this CPU fails the test.
# CI_CORE_CPU_<arch> names the features the runner must have, so that such
# a failure says why.
CI_CORE_CPU_x86_64  := avx2 sha_ni
CI_CORE_CPU_aarch64 :=

CI_JASMINC   := $(shell command -v jasminc 2>/dev/null)
CI_CORE_VARS := JASMINC=$(CI_JASMINC)
CI_NEED_JASMINC = @test -n "$(CI_JASMINC)" || { echo "$(1): jasminc is not on PATH"; exit 1; }
CI_NEED_CORE = $(if $(CI_CORE),,@echo "$(1): needs the library, but the core component is absent (none of: $(CI_DIRS_core))"; exit 1)

# logged(name, command): run command with its output in $(CI_LOGS)/name.log,
# print the log, keep the command's status.
logged = @mkdir -p $(CI_LOGS); echo "+ $(2)"; $(2) > $(CI_LOGS)/$(1).log 2>&1; rc=$$?; cat $(CI_LOGS)/$(1).log; exit $$rc

# make check writes the core transcript here.
CI_CORE_TRANSCRIPT := $(CI_BUILD)/$(CI_TARGET)/transcript-core.txt

.PHONY: ci-source ci-components ci-hash-sets ci-vectors ci-vectors-key
.PHONY: ci-test ci-test-hash ci-test-core ci-test-acvp ci-transcript ci-agree
.PHONY: ci-analysis ci-analysis-core ci-analysis-hash ci-asm ci-safety ci-safety-scope ci-diff
.PHONY: ci-proofs ci-generated

# ---------------------------------------------------------------------------
# Source checks

ci-components:
	@$(foreach c,$(CI_COMPONENTS),echo "component $(c): $(if $(call present,$(c)),present ($(call present,$(c))),absent)";)

ci-hash-sets:
ifneq ($(CI_HASH),)
	@unselected="$(filter-out $(CI_HASH_SELECTED),$(CI_HASH_VARIANTS))"; \
	missing="$(filter-out $(CI_HASH_VARIANTS),$(CI_HASH_SELECTED))"; \
	[ -z "$$unselected" ] || { echo "ci-hash-sets: variant directories no kernel set selects: $$unselected"; exit 1; }; \
	[ -z "$$missing" ] || { echo "ci-hash-sets: kernel sets select missing directories: $$missing"; exit 1; }; \
	echo "ci-hash-sets: every variant directory is selected ($(CI_HASH_VARIANTS))"
else
	$(call not_applicable,ci-hash-sets,hash)
endif

ci-source: ci-components ci-hash-sets
ifneq ($(CI_HASH),)
	$(MAKE) -C tests/hash constants generated
else
	$(call not_applicable,ci-source (hash),hash)
endif
ifneq ($(CI_PROOFS),)
	$(MAKE) -C proofs scan-admits check-constants
else
	$(call not_applicable,ci-source (proofs),proofs)
endif

# ---------------------------------------------------------------------------
# Vectors. $(CI_OUT)/vectors.txt records what was fetched, so that the
# artifact the workflow uploads is never empty.

ci-vectors:
	@mkdir -p $(CI_OUT)
	@: > $(CI_OUT)/vectors.txt
ifneq ($(CI_HASH),)
	$(MAKE) -C tests/hash vectors
	@echo "hash: NIST CAVP files fetched and verified" >> $(CI_OUT)/vectors.txt
else
	$(call not_applicable,ci-vectors (hash),hash)
	@echo "hash: NOT APPLICABLE" >> $(CI_OUT)/vectors.txt
endif
ifneq ($(CI_ACVP),)
	$(MAKE) -C tests/acvp vectors IMPL=nirapod
	@echo "acvp: NIST ACVP files fetched and verified" >> $(CI_OUT)/vectors.txt
else
	$(call not_applicable,ci-vectors (acvp),acvp)
	@echo "acvp: NOT APPLICABLE" >> $(CI_OUT)/vectors.txt
endif

# The cache key of build/vectors/acvp: the files that decide what is
# fetched, and the runner Makefile. Empty when ACVP is absent; the workflow
# then neither restores nor saves. Every file must exist.
CI_ACVP_KEY_FILES := tests/vectors/acvp/acvp.lock tests/vectors/fetch-acvp.sh tests/acvp/Makefile
CI_SHA256 := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256")

ci-vectors-key:
ifneq ($(CI_ACVP),)
	@for f in $(CI_ACVP_KEY_FILES); do [ -f $$f ] || { echo "ci-vectors-key: $$f is missing"; exit 1; }; done
	@key=acvp-$$(cat $(CI_ACVP_KEY_FILES) | $(CI_SHA256) | cut -d' ' -f1); \
	echo "acvp-key=$$key"; \
	if [ -n "$$GITHUB_OUTPUT" ]; then echo "acvp-key=$$key" >> "$$GITHUB_OUTPUT"; fi
else
	@echo "acvp-key="; if [ -n "$$GITHUB_OUTPUT" ]; then echo "acvp-key=" >> "$$GITHUB_OUTPUT"; fi
	$(call not_applicable,ci-vectors-key,acvp)
endif

# ---------------------------------------------------------------------------
# Tests

ci-test: ci-test-hash ci-test-core ci-test-acvp

ifneq ($(CI_HASH),)
ci-test-hash: ci-hash-sets $(addprefix ci-test-hash-,$(CI_HASH_SETS))
else
ci-test-hash:
	$(call not_applicable,ci-test-hash,hash)
endif

ci-test-hash-%:
	tools/ci/cpu-has.sh $(CI_HASH_CPU_$*)
	$(call logged,hash-$*,$(MAKE) -C tests/hash check negative-control $(CI_HASH_VARS_$*))
	$(CI_COUNTS) hash $(CI_LOGS)/hash-$*.log

ci-test-core:
ifneq ($(CI_CORE),)
	$(call CI_NEED_JASMINC,ci-test-core)
	tools/ci/cpu-has.sh $(CI_CORE_CPU_$(CI_ARCH))
	$(MAKE) check $(CI_CORE_VARS) TEST_CORE_FLAGS=--require-variants
	$(CI_COUNTS) transcript $(CI_CORE_TRANSCRIPT)
else
	$(call not_applicable,ci-test-core,core)
endif

# The ACVP runner tests the variant the library dispatches to on this CPU;
# the other variants are tied to it byte for byte by test_core.
ci-test-acvp:
ifneq ($(CI_ACVP),)
	$(call CI_NEED_CORE,ci-test-acvp)
	$(call CI_NEED_JASMINC,ci-test-acvp)
	tools/ci/cpu-has.sh $(CI_CORE_CPU_$(CI_ARCH))
	$(MAKE) lib $(CI_CORE_VARS)
	$(call logged,acvp,$(MAKE) -C tests/acvp check IMPL=nirapod)
	$(CI_COUNTS) acvp $(CI_LOGS)/acvp.log
	$(MAKE) -C tests/acvp controls IMPL=nirapod
else
	$(call not_applicable,ci-test-acvp,acvp)
endif

# ---------------------------------------------------------------------------
# Cross-platform agreement. ci-transcript takes the transcript that
# `make check` wrote during ci-test (run ci-test first, as the workflow
# does); a missing transcript is an error. Its line count is checked only as
# a coverage minimum (tools/ci/counts.py); its content is checked by
# ci-agree, byte for byte across the platforms. Without the core component
# every platform writes the same one-line placeholder, and ci-agree reports
# NOT APPLICABLE.

CI_TRANSCRIPT := $(CI_OUT)/transcript-$(CI_TARGET).txt

ci-transcript:
	@mkdir -p $(CI_OUT)
ifneq ($(CI_CORE),)
	@test -s $(CI_CORE_TRANSCRIPT) || { echo "ci-transcript: $(CI_CORE_TRANSCRIPT) is missing or empty; run ci-test first"; exit 1; }
	cp $(CI_CORE_TRANSCRIPT) $(CI_TRANSCRIPT)
	$(CI_COUNTS) transcript $(CI_TRANSCRIPT)
else
	@echo "NOT APPLICABLE: no core component" > $(CI_TRANSCRIPT)
	$(call not_applicable,ci-transcript,core)
endif
	@echo "ci-transcript: $(CI_TRANSCRIPT)"

CI_TRANSCRIPTS ?= $(CI_OUT)/transcripts

ci-agree:
ifneq ($(CI_CORE),)
	@test -n "$(CI_PLATFORMS)" || { echo "ci-agree: CI_PLATFORMS is not set"; exit 1; }
	@set -- $(sort $(wildcard $(CI_TRANSCRIPTS)/transcript-*.txt)); \
	[ $$# -eq $(CI_PLATFORMS) ] || { echo "ci-agree: expected $(CI_PLATFORMS) transcripts in $(CI_TRANSCRIPTS), found $$#"; exit 1; }; \
	for t in "$$@"; do \
	  [ -s "$$t" ] && ! grep -q '^NOT APPLICABLE' "$$t" \
	    || { echo "ci-agree: $$t is empty or a placeholder"; exit 1; }; \
	done; \
	first=$$1; shift; \
	for t in "$$@"; do \
	  cmp "$$first" "$$t" || { echo "ci-agree: FAIL, $$t differs from $$first"; exit 1; }; \
	done; \
	echo "ci-agree: PASS, $(CI_PLATFORMS) transcripts identical ($$(wc -l < "$$first" | tr -d ' ') lines)"
else
	$(call not_applicable,ci-agree,core)
endif

# ---------------------------------------------------------------------------
# Analysis
#
# The core's `ct` target runs jasmin-ct and jasmin-ct --sct on every unit
# and records each run in build/<target>/ct/<unit>.{ct,sct}.log; ci-analysis
# then requires one of each per unit, so that both checks are seen to have
# run. The hash tests are checked with `ct sct` per kernel set.

CI_CT_DIR := $(CI_BUILD)/$(CI_TARGET)/ct

ci-analysis: ci-analysis-core ci-analysis-hash ci-asm

ci-analysis-core:
ifneq ($(CI_CORE),)
	$(MAKE) ct
	@units=$$(ls $(CI_CT_DIR)/*.ok 2>/dev/null | wc -l | tr -d ' '); \
	ct=$$(ls $(CI_CT_DIR)/*.ct.log 2>/dev/null | wc -l | tr -d ' '); \
	sct=$$(ls $(CI_CT_DIR)/*.sct.log 2>/dev/null | wc -l | tr -d ' '); \
	[ "$$units" -gt 0 ] && [ "$$ct" = "$$units" ] && [ "$$sct" = "$$units" ] \
	  || { echo "ci-analysis-core: $$units units, $$ct ct and $$sct sct records"; exit 1; }; \
	echo "ci-analysis-core: ct and sct PASS for $$units units"
else
	$(call not_applicable,ci-analysis-core,core)
endif

ifneq ($(CI_HASH),)
ci-analysis-hash: $(addprefix ci-analysis-hash-,$(CI_HASH_SETS))
else
ci-analysis-hash:
	$(call not_applicable,ci-analysis-hash,hash)
endif

ci-analysis-hash-%:
	$(MAKE) -C tests/hash ct sct $(CI_HASH_VARS_$*)

ci-asm:
ifneq ($(CI_ASM),)
	$(call CI_NEED_JASMINC,ci-asm)
	$(MAKE) asm-policy $(CI_CORE_VARS)
else
	$(call not_applicable,ci-asm,asm)
endif

# Safety. jasmin-checksafety takes up to an hour per export today. It runs
# on every event except a pull request that changes nothing it could
# depend on: the Jasmin sources, the toolchain, its own configuration in
# analysis/safety, and the CI that runs it (CI_SAFETY_PATHS). ci-safety-scope
# decides, from the event and the files the pull request changes against
# its base (CI_EVENT, CI_BASE), and writes safety=run or safety=defer to
# $GITHUB_OUTPUT. A deferral is stated, in the log and in the job summary,
# never left silent. Without the safety component there is nothing to
# decide, and the answer is run (ci-safety then reports NOT APPLICABLE).
CI_SAFETY ?= run
CI_SAFETY_PATHS := src/jasmin toolchain analysis/safety tools/ci .github/workflows
CI_EVENT ?=
CI_BASE  ?=

ci-safety-scope:
	@decide() { echo "safety=$$1"; echo "ci-safety-scope: $$2"; \
	  if [ -n "$$GITHUB_OUTPUT" ]; then echo "safety=$$1" >> "$$GITHUB_OUTPUT"; fi; }; \
	if [ "$(CI_EVENT)" != pull_request ]; then decide run "event '$(CI_EVENT)' always runs safety"; exit 0; fi; \
	[ -n "$(CI_BASE)" ] || { echo "ci-safety-scope: a pull request needs CI_BASE"; exit 1; }; \
	changed=$$(git diff --name-only "$(CI_BASE)" HEAD) || { echo "ci-safety-scope: cannot diff against $(CI_BASE)"; exit 1; }; \
	hits=$$(printf '%s\n' "$$changed" | grep -E '^($(subst .,\.,$(subst $(eval) ,|,$(CI_SAFETY_PATHS))))/' || true); \
	if [ -n "$$hits" ]; then \
	  decide run "the pull request changes $$(printf '%s\n' "$$hits" | wc -l | tr -d ' ') file(s) under $(CI_SAFETY_PATHS)"; \
	else \
	  decide defer "the pull request changes nothing under $(CI_SAFETY_PATHS)"; \
	fi

ci-safety:
ifneq ($(CI_SAFETY_DIRS),)
ifeq ($(CI_SAFETY),run)
	$(call CI_NEED_JASMINC,ci-safety)
	$(MAKE) safety $(CI_CORE_VARS)
else ifeq ($(CI_SAFETY),defer)
	@msg="ci-safety: NOT RUN, this pull request changes nothing under $(CI_SAFETY_PATHS); jasmin-checksafety runs on main, on the schedule, and on pull requests that do"; \
	echo "$$msg"; if [ -n "$$GITHUB_STEP_SUMMARY" ]; then echo "$$msg" >> "$$GITHUB_STEP_SUMMARY"; fi
else
	@echo "ci-safety: CI_SAFETY must be run or defer, not '$(CI_SAFETY)'"; exit 1
endif
else
	$(call not_applicable,ci-safety,safety)
endif

# ---------------------------------------------------------------------------
# Differential test against slhdsa-c (PQ Code Package), a portable C
# implementation that shares no code with this one, fetched and checked by
# bench/baselines.sh against the pins of bench/baselines.lock. Every set,
# every one of the 28 interface combinations once; then the negative
# control, which must report mismatches.

CI_BASELINES := $(abspath $(CI_BUILD)/baselines)
CI_DIFF_SEED ?= 20261012
CI_ORACLE_NIRAPOD := $(CI_BUILD)/harness/nirapod-$(CI_TARGET)/oracle
CI_ORACLE_SLHDSA_C := $(CI_BUILD)/harness/slhdsa-c/oracle
CI_DIFFTEST = $(CI_PYTHON) -I tests/diff/difftest.py --a=$(CI_ORACLE_NIRAPOD) --b=$(CI_ORACLE_SLHDSA_C) \
              --seed=$(CI_DIFF_SEED) --sets=all

ci-diff:
ifneq ($(CI_DIFF),)
	$(call CI_NEED_CORE,ci-diff)
	$(call CI_NEED_JASMINC,ci-diff)
	bench/baselines.sh fetch $(CI_BASELINES)
	$(MAKE) lib $(CI_CORE_VARS)
	$(MAKE) -C tests/diff IMPL=nirapod
	$(MAKE) -C tests/diff IMPL=slhdsa-c BASELINES=$(CI_BASELINES)
	$(call logged,diff,$(CI_DIFFTEST) --count=28)
	$(CI_COUNTS) diff $(CI_LOGS)/diff.log
	@mkdir -p $(CI_LOGS); $(CI_DIFFTEST) --count=1 --control=corrupt-b > $(CI_LOGS)/diff-control.log 2>&1; \
	rc=$$?; cat $(CI_LOGS)/diff-control.log; \
	[ $$rc = 1 ] || { echo "ci-diff: the negative control exited $$rc, expected 1 (mismatches)"; exit 1; }
	$(CI_COUNTS) diff-control $(CI_LOGS)/diff-control.log
else
	$(call not_applicable,ci-diff,diff)
endif

# ---------------------------------------------------------------------------
# Proofs and generated assembly

ci-proofs:
ifneq ($(CI_PROOFS),)
	$(MAKE) -C proofs check check-extraction
else
	$(call not_applicable,ci-proofs,proofs)
endif

ci-generated:
ifneq ($(CI_GEN),)
	$(call CI_NEED_JASMINC,ci-generated)
	$(MAKE) gen-check $(CI_CORE_VARS)
else
	$(call not_applicable,ci-generated,gen)
endif
