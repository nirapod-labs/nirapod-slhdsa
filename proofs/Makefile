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
#   make check-own        proofs/spec and proofs/security, without the scans
#   make check-spec       the scans, then proofs/spec only
#   make check-imported   the imported crypto-specs theories, re-checked here
#   make check-formosa    the imported SPHINCS+ security proof, re-checked here
#   make check-correctness the correctness proofs, once per extracted model
#   make check-pair PAIR=<arch>/<variant>   one model only
#   make check-shard SHARD=<shard>  one shard of CI (below), J files at once
#   make list-shards      the shards
#   make shard-files      every file each shard checks, "<shard> <path>"
#   make scan-admits      fail if any checked file contains a proof hole or
#                         a command that skips checking (admit, admitted,
#                         pragma, exit, fail)
#   make check-constants  re-derive the FIPS 180-4 constant tables and compare
#   make check-inventory  fail unless EasyCrypt's list of the axioms in scope,
#                         the claimed theorem statements and the definitions
#                         equal the committed inventory/<arch>-<variant>.txt
#   make check-inventory-files  fail if an inventory file is not that of a
#                         pair in EXTRACTIONS (no EasyCrypt needed)
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
# Files are checked J at a time (default 1; tools/check_files.py), each in
# its own EasyCrypt process.
#
# Variables: EASYCRYPT (the binary of the pinned toolchain), EC_PROVERS and
# EC_TIMEOUT (this project's theories), IMPORTED_PROVERS and
# IMPORTED_TIMEOUT (the imported crypto-specs theories), FORMOSA_PROVERS
# and FORMOSA_TIMEOUT (the imported security proof), JASMIN2EC and
# JASMIN_SRC (the pinned jasmin2ec and the root of the Jasmin sources, for
# extraction), PYTHON (the scans).

EASYCRYPT  ?= easycrypt
JASMIN2EC  ?= jasmin2ec
PYTHON     ?= python3
JASMIN_SRC ?= ../src
J          ?= 1

CRYPTO_SPECS := ../third_party/crypto-specs
FORMOSA      := ../third_party/formosa-slhdsa

EC_PATH := -R spec -R security -I $(FORMOSA)/proofs \
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

# The imported crypto-specs theories load only their own roots, so that
# they can be checked, and keyed in CI, apart from this project's theories.
IMPORTED_PATH := -R $(CRYPTO_SPECS)/common -R $(CRYPTO_SPECS)/fips202 \
                 -I JazzEC:$(CRYPTO_SPECS)/arrays

OWN_FLAGS      := -no-eco $(EC_PATH) $(EC_PROVERS) -timeout $(EC_TIMEOUT)
IMPORTED_FLAGS := -no-eco $(IMPORTED_PATH) $(IMPORTED_PROVERS) -timeout $(IMPORTED_TIMEOUT)

# The SPHINCS+ security proof keeps the prover selection and timeout of its
# own easycrypt.project.
FORMOSA_PROVERS ?= -p Alt-Ergo@2.6 -p CVC5@1.0 -p Z3@4.12
FORMOSA_TIMEOUT ?= 11
FORMOSA_FLAGS   := -no-eco -I $(FORMOSA)/proofs $(FORMOSA_PROVERS) -timeout $(FORMOSA_TIMEOUT)

OWN_FILES      := $(shell find spec security \
                    \( -name '*.ec' -o -name '*.eca' \) 2>/dev/null | LC_ALL=C sort)
SPEC_FILES     := $(filter spec/%,$(OWN_FILES))

# ------------------------------------------------------------------
# Correctness proofs, checked once per extracted model
#
# Layout and naming (one convention for every proof of extracted code):
#
#   extracted/<arch>/<variant>/       the models: HashExtracted, AddressExtracted (+ arrays)
#   correctness/<area>/...            shared proofs, any directory whose
#                                     path has no architecture component;
#                                     checked against every pair, except
#                                     a proof of one kernel (KERNEL_PROOFS)
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
# A shared proof of a kernel holds only for the pairs that build that
# kernel. KERNEL_PROOFS lists each such proof with the kernel root it
# requires, as <file>:<role>=<root> with the role and root of EXTRACTIONS;
# a pair checks the proof when its root for that role is the one listed.
# Every other shared proof is checked against every pair.
KERNEL_PROOFS := \
  correctness/hash/Keccakf1600_Portable.ec:KeccakKernel=keccak \
  correctness/hash/SHA256_Compress.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA256_Blocks.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA512_Compress.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA512_Blocks.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA256_Stream.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA512_Stream.ec:Sha2Kernel=sha2 \
  correctness/hash/HMAC_SHA256.ec:Sha2Kernel=sha2 \
  correctness/hash/HMAC_SHA512.ec:Sha2Kernel=sha2 \
  correctness/hash/MGF1_SHA256.ec:Sha2Kernel=sha2
role_field_KeccakKernel  := 3
role_field_KeccakKernelX := 4
role_field_Sha2Kernel    := 5
role_field_Sha2KernelX   := 6
pair_entry   = $(subst :, ,$(filter $(1):%,$(EXTRACTIONS)))
kp_file      = $(firstword $(subst :, ,$(1)))
kp_role      = $(firstword $(subst =, ,$(lastword $(subst :, ,$(1)))))
kp_root      = $(lastword $(subst =, ,$(1)))
kp_holds     = $(filter $(call kp_root,$(2)),$(word $(role_field_$(call kp_role,$(2))),$(call pair_entry,$(1))))
pair_kernel_proofs = $(foreach k,$(KERNEL_PROOFS),$(if $(call kp_holds,$(1),$(k)),$(call kp_file,$(k))))
pair_shared  = $(filter-out $(foreach k,$(KERNEL_PROOFS),$(call kp_file,$(k))),$(SHARED_PROOFS)) \
               $(call pair_kernel_proofs,$(1))
pair_files   = $(sort $(wildcard extracted/$(1)/*.ec) \
                 $(foreach d,$(call pair_dirs,$(1)),$(wildcard $(d)/*.ec $(d)/*.eca)) \
                 $(call pair_shared,$(1)))
pair_flags   = -no-eco $(EC_PATH) -I extracted/$(1) \
               $(foreach d,$(SHARED_PROOF_DIRS) $(call pair_dirs,$(1)),-I $(d)) \
               $(EC_PROVERS) -timeout $(EC_TIMEOUT)
IMPORTED_FILES := $(shell find $(CRYPTO_SPECS) \( -name '*.ec' -o -name '*.eca' \) \
                    2>/dev/null | LC_ALL=C sort)
FORMOSA_FILES  := $(shell find $(FORMOSA)/proofs \( -name '*.ec' -o -name '*.eca' \) \
                    2>/dev/null | LC_ALL=C sort)

.PHONY: check check-spec check-own check-imported check-formosa check-correctness scan-admits check-constants

check: scan-admits check-constants check-imported check-formosa check-own check-correctness

check-spec: scan-admits check-constants
	@$(MAKE) --no-print-directory LABEL=check-spec FILES="$(SPEC_FILES)" FLAGS="$(OWN_FLAGS)" compile-files

check-own:
	@$(MAKE) --no-print-directory LABEL=check-own FILES="$(OWN_FILES)" FLAGS="$(OWN_FLAGS)" compile-files

check-imported:
	@$(MAKE) --no-print-directory LABEL=check-imported FILES="$(IMPORTED_FILES)" FLAGS="$(IMPORTED_FLAGS)" compile-files

check-formosa:
	@$(MAKE) --no-print-directory LABEL=check-formosa FILES="$(FORMOSA_FILES)" FLAGS="$(FORMOSA_FLAGS)" compile-files

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
	@$(PYTHON) -I tools/scan_holes.py $(OWN_FILES) $(IMPORTED_FILES) $(FORMOSA_FILES) \
	  $(shell find correctness extracted \( -name '*.ec' -o -name '*.eca' \) 2>/dev/null) \
	  && echo "scan-admits: PASS" \
	  || { echo "scan-admits: FAIL"; exit 1; }

check-constants:
	@$(PYTHON) -I tools/sha2_constants.py spec/hash/FIPS180_SHA2.ec

# ------------------------------------------------------------------
# Axiom, theorem and definition inventory
#
# For each pair, tools/inventory.py requires every theory checked for that
# pair and records what EasyCrypt prints for `print axiom` (every axiom in
# scope, whether declared, given by `axiomatized by`, or left unrealized by
# a clone), the statements of THEOREMS, and the definitions of every theory
# outside extracted/ (which check-extraction pins). check-inventory fails on
# any difference from the committed file, and on an inventory file of a
# pair that is no longer extracted.

THEOREMS := \
  SHA256_Compress.sha256_rounds_correct SHA256_Compress.sha256_compress_correct \
  SHA256_Compress.sha256_compress_total \
  SHA512_Compress.sha512_rounds_correct SHA512_Compress.sha512_compress_correct \
  SHA512_Compress.sha512_compress_total

# The kernels' entry points that read whole blocks from memory.
THEOREMS += SHA256_Blocks.sha256_compress_one_total SHA256_Blocks.sha256_compress_blocks_total \
            SHA512_Blocks.sha512_compress_one_total SHA512_Blocks.sha512_compress_blocks_total

# The streaming hashes (absorb from memory, pad and finalize) and the one-shot
# hashes built on them.
THEOREMS += SHA256_Stream.sha256_absorb_mem_total SHA256_Stream.sha256_finalize_total \
            SHA256_Stream.sha256_mem_total SHA256_Stream.sha224_mem_total \
            SHA512_Stream.sha512_absorb_mem_total SHA512_Stream.sha512_finalize_total \
            SHA512_Stream.sha512_mem_total SHA512_Stream.sha384_mem_total \
            SHA512_Stream.sha512_224_mem_total SHA512_Stream.sha512_256_mem_total

# HMAC over the streaming hashes: the keyed initial states, the outer hash,
# and the specification lemma that ties them to FIPS 198-1 for short keys.
THEOREMS += HMAC_SHA256.hmac_sha256_blocks HMAC_SHA256.hmac_sha256_init_total \
            HMAC_SHA256.hmac_sha256_finalize_total \
            HMAC_SHA512.hmac_sha512_blocks HMAC_SHA512.hmac_sha512_init_total \
            HMAC_SHA512.hmac_sha512_finalize_total

# MGF1 over SHA-256 for the two (seed, output) lengths of the n = 16 SHA2 sets.
THEOREMS += MGF1_SHA256.mgf64_30_sha256_total MGF1_SHA256.mgf64_34_sha256_total

# Keccak-f[1600] of the shared scalar kernel; the AArch64 kernel that keeps
# the state in registers has its own (KERNEL_THEOREMS_aarch64_a64scalar).
THEOREMS += Keccakf1600_Portable.keccak_round_correct Keccakf1600_Portable.keccakf1600_correct \
            Keccakf1600_Portable.keccakf1600_total

# The address setters of the SLH-DSA core against FIPS 205 Table 1.
ADRS_THEOREMS := adrs_zero_correct adrs_set_layer_correct adrs_set_tree_correct \
                 adrs_set_type_and_clear_correct adrs_set_keypair_correct \
                 adrs_copy_keypair_correct adrs_set_chain_correct \
                 adrs_set_tree_height_correct adrs_set_hash_correct \
                 adrs_set_tree_index_correct adrs_copy_correct
THEOREMS += $(foreach t,$(ADRS_THEOREMS),ADRS.$(t))

# EUF-CMA of the specification, per parameter set: the deterministic and
# hedged theorems on the spec's own SLH_DSA module (_spec), the same bounds
# for the internal scheme behind the framing, and the game equalities that
# link the two.
SLHDSA_SETS := SHA2_128S SHAKE_128S SHA2_128F SHAKE_128F SHA2_192S SHAKE_192S \
               SHA2_192F SHAKE_192F SHA2_256S SHAKE_256S SHA2_256F SHAKE_256F
SLHDSA_THEOREMS := slhdsa_euf_cma_spec slhdsa_euf_cma_hedged_spec \
                   slhdsa_euf_cma slhdsa_euf_cma_hedged spec_det_eq spec_hedged_eq
THEOREMS += $(foreach s,$(SLHDSA_SETS),$(foreach t,$(SLHDSA_THEOREMS),SPHINCS_Sets.SLH_DSA_$(s).$(t)))

# The theorems of one pair: those of the theories it checks (a KernelSpec
# is named by pair, KERNEL_THEOREMS_<arch>_<variant>).
KERNEL_THEOREMS_aarch64_a64scalar := KernelSpec.keccak_round_regs_correct \
  KernelSpec.keccakf1600_correct KernelSpec.keccakf1600_total
thm_theory   = $(firstword $(subst ., ,$(1)))
pair_loaded  = $(basename $(notdir $(OWN_FILES) $(IMPORTED_FILES) $(FORMOSA_FILES) \
                 $(call pair_shared,$(1))))
pair_theorems = $(foreach t,$(THEOREMS),$(if $(filter $(call thm_theory,$(t)),$(call pair_loaded,$(1))),$(t))) \
                $(KERNEL_THEOREMS_$(subst /,_,$(1)))

inventory_file = inventory/$(subst /,-,$(1)).txt

.PHONY: inventory check-inventory inventory-pair
inventory:
	@mkdir -p inventory
	@for p in $(PAIRS); do \
	  $(MAKE) --no-print-directory PAIR=$$p MODE=write inventory-pair || exit 1; \
	done

check-inventory: check-inventory-files
	@for p in $(PAIRS); do \
	  $(MAKE) --no-print-directory PAIR=$$p MODE=check inventory-pair || exit 1; \
	done
	@echo "check-inventory: PASS"

.PHONY: check-inventory-files
check-inventory-files:
	@expected="$(foreach p,$(PAIRS),$(call inventory_file,$(p)))"; \
	for f in inventory/*; do \
	  case " $$expected " in *" $$f "*) ;; \
	    *) echo "check-inventory-files: FAIL ($$f is not the inventory of a pair in EXTRACTIONS)"; exit 1;; \
	  esac; \
	done; echo "check-inventory-files: PASS"

inventory-pair:
	@test -n "$(PAIR)" || { echo "inventory-pair: PAIR not set"; exit 1; }
	@$(PYTHON) -I tools/inventory.py --pair $(PAIR) --easycrypt "$(EASYCRYPT)" \
	  --flags "$(call pair_flags,$(PAIR))" --namespace JazzEC=$(CRYPTO_SPECS)/arrays \
	  --generated extracted --theorems "$(call pair_theorems,$(PAIR))" --$(MODE) $(call inventory_file,$(PAIR)) \
	  $(OWN_FILES) $(IMPORTED_FILES) $(FORMOSA_FILES) $(call pair_files,$(PAIR))

# ------------------------------------------------------------------
# Extraction
#
# Each (architecture, variant) pair is one extraction of extracted/hash.jazz
# and extracted/address.jazz into extracted/<arch>/<variant>/, the first
# under the include roots that select the pair's kernels. The theories of
# the extracted programs are always HashExtracted and AddressExtracted, so
# the correctness proofs, which require them by those names, are checked
# once per pair against that pair's models. tools/extract.sh adds the
# generated-file headers.

HASH_SRC   := $(JASMIN_SRC)/hash
SLHDSA_SRC := $(JASMIN_SRC)/slhdsa

# <arch>/<variant>:<jasmin arch>:<KeccakKernel>:<KeccakKernelX>:<Sha2Kernel>:<Sha2KernelX>
#
# portable: every kernel root at its portable default. aarch64/a64scalar:
# the single-way Keccak kernel of the AArch64 scalar variant (top-level
# Makefile, SCALAR_K1), which keeps the state in registers; its other
# roots are those that variant builds (LIBRARY_PAIRS below).
EXTRACTIONS := \
  x86_64/portable:x86-64:keccak:keccak:sha2:sha2 \
  aarch64/portable:armv8a:keccak:keccak:sha2:sha2 \
  aarch64/a64scalar:armv8a:keccak/aarch64/scalar:keccak:sha2:sha2

# The library variant each pair models: <arch>/<variant of the top-level
# Makefile>=<pair>. ci/kernel_roots.py fails unless every variant the
# library builds is bound here or listed in LIBRARY_UNMODELLED, and every
# bound pair's EXTRACTIONS roots are the roots the library compiles that
# variant with; so a change to the library's kernel selection that the
# models do not follow fails CI. The portable pairs model no library
# variant on AArch64; they check the shared kernels on both architectures.
LIBRARY_PAIRS      := x86_64/scalar=x86_64/portable aarch64/scalar=aarch64/a64scalar
LIBRARY_UNMODELLED := x86_64/avx2 x86_64/shani aarch64/sha2 aarch64/sha3

.PHONY: print-library-pairs
print-library-pairs:
	@echo "extractions $(EXTRACTIONS)"
	@echo "pairs $(LIBRARY_PAIRS)"
	@echo "unmodelled $(LIBRARY_UNMODELLED)"

.PHONY: extract check-extraction
extract:
	@for e in $(EXTRACTIONS); do \
	  JASMIN2EC="$(JASMIN2EC)" HASH_SRC="$(HASH_SRC)" SLHDSA_SRC="$(SLHDSA_SRC)" sh tools/extract.sh "$$e" extracted || exit 1; \
	done

check-extraction:
	@tmp=$$(mktemp -d) || exit 1; \
	for e in $(EXTRACTIONS); do \
	  JASMIN2EC="$(JASMIN2EC)" HASH_SRC="$(HASH_SRC)" SLHDSA_SRC="$(SLHDSA_SRC)" sh tools/extract.sh "$$e" "$$tmp" || { rm -rf "$$tmp"; exit 1; }; \
	  d=$${e%%:*}; \
	  diff -r "$$tmp/$$d" "extracted/$$d" > /dev/null \
	    || { echo "check-extraction: FAIL ($$d differs from a fresh extraction)"; rm -rf "$$tmp"; exit 1; }; \
	done; rm -rf "$$tmp"; \
	expected="$(foreach e,$(EXTRACTIONS),extracted/$(firstword $(subst :, ,$(e))))"; \
	for d in extracted/*/*; do \
	  case " $$expected " in *" $$d "*) ;; \
	    *) echo "check-extraction: FAIL ($$d is not a pair in EXTRACTIONS)"; exit 1;; \
	  esac; \
	done; echo "check-extraction: PASS ($(words $(EXTRACTIONS)) pairs)"

.PHONY: compile-files
# Each file is checked on its own, from a scratch copy that ends with a
# trivial lemma, J at a time (tools/check_files.py): EasyCrypt accepts a
# file that ends while obligations of a `clone ... proof *` are still
# unrealized, and then treats them as proven; any command after them is
# rejected ("cannot process [axiom] inside a proof script"). The sentinel
# lemma makes such a file fail.
compile-files:
	@test -n "$(LABEL)" || { echo "compile-files: LABEL not set"; exit 1; }
	@$(PYTHON) -I tools/check_files.py --label "$(LABEL)" --jobs $(J) \
	  --easycrypt "$(EASYCRYPT)" --flags "$(FLAGS)" $(FILES)

# ------------------------------------------------------------------
# Shards
#
# CI checks the development in shards, in parallel jobs, each keyed on the
# files it can load (ci/checks.toml); together they check what
# `check` checks, apart from the scans and the constant check, which CI
# runs without EasyCrypt:
#
#   sphincs       the imported SPHINCS+ proof (check-formosa)
#   crypto-specs  the imported crypto-specs theories (check-imported)
#   spec          this project's specification and security theories
#                 (check-own)
#   x86_64        the correctness proofs against every x86-64 model, then
#                 the inventory of each such pair
#   aarch64       the same for AArch64
#   extraction    the committed models against a fresh extraction
#
# Every .ec and .eca file under this directory and ../third_party belongs
# to exactly one shard, except the shared correctness proofs, which every
# pair shard checks against its own model (`shard-files`; CI checks this).

SHARDS := sphincs crypto-specs spec x86_64 aarch64 extraction
pairs_of = $(filter $(1)/%,$(PAIRS))

.PHONY: list-shards shard-files check-shard
list-shards:
	@echo $(SHARDS)

# Paths from the repository root.
root_path = $(patsubst ../%,%,$(patsubst %,proofs/%,$(filter-out ../%,$(1))) $(filter ../%,$(1)))
shard-files:
	@$(foreach f,$(call root_path,$(FORMOSA_FILES)),echo "sphincs $(f)";)
	@$(foreach f,$(call root_path,$(IMPORTED_FILES)),echo "crypto-specs $(f)";)
	@$(foreach f,$(call root_path,$(OWN_FILES)),echo "spec $(f)";)
	@$(foreach a,$(ARCHS),$(foreach p,$(call pairs_of,$(a)),$(foreach f,$(call root_path,$(call pair_files,$(p))),echo "$(a) $(f)";)))

check-shard:
	@case " $(SHARDS) " in *" $(SHARD) "*) ;; *) echo "check-shard: unknown shard '$(SHARD)' (one of: $(SHARDS))"; exit 1;; esac
ifeq ($(SHARD),sphincs)
	@$(MAKE) --no-print-directory LABEL="shard sphincs" FILES="$(FORMOSA_FILES)" FLAGS="$(FORMOSA_FLAGS)" compile-files
else ifeq ($(SHARD),crypto-specs)
	@$(MAKE) --no-print-directory LABEL="shard crypto-specs" FILES="$(IMPORTED_FILES)" FLAGS="$(IMPORTED_FLAGS)" compile-files
else ifeq ($(SHARD),spec)
	@$(MAKE) --no-print-directory LABEL="shard spec" FILES="$(OWN_FILES)" FLAGS="$(OWN_FLAGS)" compile-files
else ifeq ($(SHARD),extraction)
	@$(MAKE) --no-print-directory check-extraction
else
	@test -n "$(call pairs_of,$(SHARD))" || { echo "check-shard: no pair of $(SHARD) in EXTRACTIONS"; exit 1; }
	@for p in $(call pairs_of,$(SHARD)); do \
	  $(MAKE) --no-print-directory PAIR=$$p check-pair || exit 1; \
	  $(MAKE) --no-print-directory PAIR=$$p MODE=check inventory-pair || exit 1; \
	done
endif
