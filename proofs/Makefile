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
#   make check-set PAIR=<pair> SET=<set>    the per-set proofs, one set's model
#   make check-sets PAIR=<pair>             the same for every set of CORE_SETS
#   make check-shard SHARD=<shard>  one shard of CI (below), J files (or, for
#                         the inventory shard, J pairs) at once
#   make list-shards      the shards
#   make shard-files      every file each shard checks, "<shard> <path>"
#   make scan-admits      fail if any checked file contains a proof hole or
#                         a command that skips checking (admit, admitted,
#                         pragma, exit, fail)
#   make check-constants  re-derive the FIPS 180-4 constant tables and compare
#   make check-inventory  fail unless EasyCrypt's list of the axioms in scope,
#                         the claimed theorem statements and the definitions
#                         equal the committed inventory/<arch>-<variant>.txt
#                         and inventory/sets/<arch>-<variant>-<set>.txt
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
#   extracted/<arch>/<variant>/sets/<set>/  the model of one parameter-set
#                                     unit (CoreExtracted), the names the
#                                     per-set proofs use for it (SetModel)
#                                     and the array theories it requires
#                                     that the pair's models do not
#   correctness/core/                 per-set proofs: checked against each
#                                     set's model of each pair in CORE_PAIRS
#   correctness/core/<family>/        the same, for the sets of one hash
#                                     family only (sha2, shake)
#
# A pair is checked with its model, its architecture and variant
# directories and every shared directory on the load path, so a shared
# proof that requires HashExtracted, ArchWord or KernelSpec is checked
# against that pair's versions. Theory names must be unique on that path.
ARCHS := x86_64 aarch64
PAIRS = $(foreach e,$(EXTRACTIONS),$(firstword $(subst :, ,$(e))))

archpat := $(foreach a,$(ARCHS),-e '/$(a)/' -e '/$(a)$$')
SHARED_PROOF_DIRS = $(shell find correctness -type d 2>/dev/null | grep -v $(archpat) \
                      | grep -v -e '^correctness/core$$' -e '^correctness/core/' | LC_ALL=C sort)
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
  correctness/hash/Sponge_Portable.ec:KeccakKernel=keccak \
  correctness/hash/SHA256_Compress.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA256_Blocks.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA512_Compress.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA512_Blocks.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA256_Stream.ec:Sha2Kernel=sha2 \
  correctness/hash/SHA512_Stream.ec:Sha2Kernel=sha2 \
  correctness/hash/HMAC_SHA256.ec:Sha2Kernel=sha2 \
  correctness/hash/HMAC_SHA512.ec:Sha2Kernel=sha2 \
  correctness/hash/MGF1_SHA256.ec:Sha2Kernel=sha2 \
  correctness/hash/MGF1_SHA512.ec:Sha2Kernel=sha2
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
# Per-set proofs. jasmin2ec substitutes the parameters of a set into the
# code, so a proof about the core is checked once per set, against the
# model of that set's compilation unit. A per-set proof names the set's
# parameters and array theories only through SetModel (tools/set_model.py),
# so one proof text serves every set. The per-set models are extracted for
# the pairs that model a library variant (CORE_PAIRS: LIBRARY_PAIRS below).
CORE_SETS  := sha2_128s shake_128s sha2_128f shake_128f sha2_192s shake_192s \
              sha2_192f shake_192f sha2_256s shake_256s sha2_256f shake_256f
CORE_PAIRS  = $(foreach b,$(LIBRARY_PAIRS),$(lastword $(subst =, ,$(b))))
set_family  = $(firstword $(subst _, ,$(1)))
set_dirs    = correctness/core $(wildcard correctness/core/$(call set_family,$(1)))
set_proofs  = $(sort $(foreach d,$(call set_dirs,$(1)),$(wildcard $(d)/*.ec $(d)/*.eca)))
set_dir     = extracted/$(1)/sets/$(2)
set_files   = $(sort $(wildcard $(call set_dir,$(1),$(2))/*.ec)) $(call set_proofs,$(2))
set_flags   = $(call pair_flags,$(1)) -I $(call set_dir,$(1),$(2)) \
              $(foreach d,$(call set_dirs,$(2)),-I $(d))

# CI checks the per-set proofs in groups of sets (shards <pair>-<group>,
# below), so that no job checks all twelve: a group is a hash family and
# the s or f sets of FIPS 205 Table 2. Every set is in exactly one group.
SET_GROUPS := sha2-s:sha2_128s,sha2_192s,sha2_256s sha2-f:sha2_128f,sha2_192f,sha2_256f \
              shake-s:shake_128s,shake_192s,shake_256s shake-f:shake_128f,shake_192f,shake_256f
comma      := ,
group_name  = $(firstword $(subst :, ,$(1)))
group_sets  = $(subst $(comma), ,$(lastword $(subst :, ,$(1))))
grouped_sets := $(foreach g,$(SET_GROUPS),$(call group_sets,$(g)))
ifneq ($(sort $(grouped_sets)) $(words $(grouped_sets)),$(sort $(CORE_SETS)) $(words $(CORE_SETS)))
$(error SET_GROUPS must hold every set of CORE_SETS exactly once)
endif

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
	@for p in $(CORE_PAIRS); do \
	  $(MAKE) --no-print-directory PAIR=$$p check-sets || exit 1; \
	done

.PHONY: check-pair
check-pair:
	@test -n "$(PAIR)" || { echo "check-pair: PAIR not set"; exit 1; }
	@$(MAKE) --no-print-directory LABEL="check-pair $(PAIR)" FILES="$(call pair_files,$(PAIR))" \
	  FLAGS="$(call pair_flags,$(PAIR))" compile-files

.PHONY: check-set check-sets
check-set:
	@test -n "$(PAIR)" -a -n "$(SET)" || { echo "check-set: PAIR or SET not set"; exit 1; }
	@case " $(CORE_PAIRS) " in *" $(PAIR) "*) ;; *) echo "check-set: $(PAIR) is not in CORE_PAIRS"; exit 1;; esac
	@case " $(CORE_SETS) " in *" $(SET) "*) ;; *) echo "check-set: $(SET) is not in CORE_SETS"; exit 1;; esac
	@$(MAKE) --no-print-directory LABEL="check-set $(PAIR)/$(SET)" FILES="$(call set_files,$(PAIR),$(SET))" \
	  FLAGS="$(call set_flags,$(PAIR),$(SET))" compile-files

check-sets:
	@n=0; for s in $(CORE_SETS); do \
	  $(MAKE) --no-print-directory PAIR=$(PAIR) SET=$$s check-set || exit 1; n=$$((n + 1)); \
	done; echo "check-sets $(PAIR): PASS $$n sets"

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

# MGF1 for the (seed, output) lengths of the SHA2 sets: SHA-256 for n = 16,
# SHA-512 for n = 24 and 32.
THEOREMS += MGF1_SHA256.mgf64_30_sha256_total MGF1_SHA256.mgf64_34_sha256_total \
            MGF1_SHA512.mgf112_39_sha512_total MGF1_SHA512.mgf112_42_sha512_total \
            MGF1_SHA512.mgf128_47_sha512_total MGF1_SHA512.mgf128_49_sha512_total

# Keccak-f[1600] of the shared scalar kernel; the AArch64 kernel that keeps
# the state in registers has its own (KERNEL_THEOREMS_aarch64_a64scalar).
THEOREMS += Keccakf1600_Portable.keccak_round_correct Keccakf1600_Portable.keccakf1600_correct \
            Keccakf1600_Portable.keccakf1600_ll Keccakf1600_Portable.keccakf1600_total

# The Keccak sponge (absorb from memory, finalize); pair-generic, with the
# correctness and termination of _keccakf1600 as premises.
THEOREMS += Sponge.keccak_absorb_mem_h Sponge.keccak_absorb_mem_ll \
            Sponge.keccak_absorb_mem_total Sponge.keccak_finalize_h \
            Sponge.keccak_finalize_ll Sponge.keccak_finalize_total

# The sponge squeeze to memory and the one-shot SHA-3 and SHAKE functions;
# pair-generic, with the same premises.
THEOREMS += SpongeSqueeze.extract_mem_h SpongeSqueeze.extract_mem_ll \
            SpongeSqueeze.keccak_squeeze_mem_h SpongeSqueeze.keccak_squeeze_mem_ll \
            SpongeSqueeze.keccak_squeeze_mem_total
THEOREMS += SHA3_SHAKE.sha3_absorb_all_total SHA3_SHAKE.sha3_224_mem_total \
            SHA3_SHAKE.sha3_256_mem_total SHA3_SHAKE.sha3_384_mem_total \
            SHA3_SHAKE.sha3_512_mem_total SHA3_SHAKE.shake_mem_total \
            SHA3_SHAKE.shake128_mem_total SHA3_SHAKE.shake256_mem_total

# The total-correctness sponge, SHA-3 and SHAKE theorems above, with both
# premises discharged by the portable Keccak-f[1600] theorems, on the pairs
# that build that kernel; aarch64/a64scalar has its own (Sponge_KernelSpec,
# below).
SPONGE_THEOREMS := keccak_absorb_mem_total keccak_finalize_total keccak_squeeze_mem_total \
                   sha3_absorb_all_total sha3_224_mem_total sha3_256_mem_total \
                   sha3_384_mem_total sha3_512_mem_total shake_mem_total \
                   shake128_mem_total shake256_mem_total
THEOREMS += $(foreach t,$(SPONGE_THEOREMS),Sponge_Portable.$(t))

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
  KernelSpec.keccakf1600_correct KernelSpec.keccakf1600_ll KernelSpec.keccakf1600_total \
  $(foreach t,$(SPONGE_THEOREMS),Sponge_KernelSpec.$(t))
thm_theory   = $(firstword $(subst ., ,$(1)))
pair_loaded  = $(basename $(notdir $(OWN_FILES) $(IMPORTED_FILES) $(FORMOSA_FILES) \
                 $(call pair_shared,$(1))))
pair_theorems = $(foreach t,$(THEOREMS),$(if $(filter $(call thm_theory,$(t)),$(call pair_loaded,$(1))),$(t))) \
                $(KERNEL_THEOREMS_$(subst /,_,$(1)))

inventory_file = inventory/$(subst /,-,$(1)).txt
set_inventory_file = inventory/sets/$(subst /,-,$(1))-$(2).txt

# The theorems of the per-set proofs, pinned once per (pair, set) in
# inventory/sets/<arch>-<variant>-<set>.txt, whose definitions are those of the
# per-set proofs (the spec's are pinned by the pair inventories).
SET_THEOREMS := Encoding.node_copy_correct Encoding.node_concat_correct \
                DigestIndices.digest_tree_leaf_correct DigestIndices.fors_indices_correct \
                Wots.wots_digits_correct \
                ADRSc.adrs_compress_into64_correct ADRSc.adrs_compress_into128_correct \
                Thash.thash_f_correct Thash.thash_prf_correct Thash.thash_h_correct
set_theorems  = $(foreach t,$(SET_THEOREMS),$(if $(filter $(call thm_theory,$(t)),$(basename $(notdir $(call set_proofs,$(1))))),$(t)))
set_inventories = $(foreach p,$(CORE_PAIRS),$(foreach s,$(CORE_SETS),$(call set_inventory_file,$(p),$(s))))

.PHONY: inventory check-inventory inventory-pair
inventory:
	@mkdir -p inventory/sets
	@for p in $(PAIRS); do \
	  $(MAKE) --no-print-directory PAIR=$$p MODE=write inventory-pair || exit 1; \
	done
	@for p in $(CORE_PAIRS); do for s in $(CORE_SETS); do \
	  $(MAKE) --no-print-directory PAIR=$$p SET=$$s MODE=write inventory-set || exit 1; \
	done; done

check-inventory: check-inventory-files
	@for p in $(PAIRS); do \
	  $(MAKE) --no-print-directory PAIR=$$p MODE=check inventory-pair || exit 1; \
	done
	@for p in $(CORE_PAIRS); do for s in $(CORE_SETS); do \
	  $(MAKE) --no-print-directory PAIR=$$p SET=$$s MODE=check inventory-set || exit 1; \
	done; done
	@echo "check-inventory: PASS"

.PHONY: check-inventory-files
check-inventory-files:
	@expected="$(foreach p,$(PAIRS),$(call inventory_file,$(p))) $(set_inventories)"; \
	for f in $$(find inventory -type f | LC_ALL=C sort); do \
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

inventory-set:
	@test -n "$(PAIR)" -a -n "$(SET)" || { echo "inventory-set: PAIR or SET not set"; exit 1; }
	@$(PYTHON) -I tools/inventory.py --pair $(PAIR)/$(SET) --easycrypt "$(EASYCRYPT)" \
	  --flags "$(call set_flags,$(PAIR),$(SET))" --namespace JazzEC=$(CRYPTO_SPECS)/arrays \
	  --generated extracted --theorems "$(call set_theorems,$(SET))" --allow-no-definitions \
	  --$(MODE) $(call set_inventory_file,$(PAIR),$(SET)) $(call set_files,$(PAIR),$(SET))

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
	@echo "sets $(CORE_SETS)"

.PHONY: extract check-extraction
# extract_one(entry, outroot): one EXTRACTIONS entry, with the per-set
# models when its pair is in CORE_PAIRS.
ent_pair    = $(firstword $(subst :, ,$(1)))
extract_one = JASMIN2EC="$(JASMIN2EC)" HASH_SRC="$(HASH_SRC)" SLHDSA_SRC="$(SLHDSA_SRC)" \
  PYTHON="$(PYTHON)" CORE_SETS="$(if $(filter $(call ent_pair,$(1)),$(CORE_PAIRS)),$(CORE_SETS))" \
  sh tools/extract.sh "$(1)" $(2)

extract:
	@$(foreach e,$(EXTRACTIONS),$(call extract_one,$(e),extracted) || exit 1;)

check-extraction:
	@tmp=$$(mktemp -d) || exit 1; \
	$(foreach e,$(EXTRACTIONS),$(call extract_one,$(e),"$$tmp") || { rm -rf "$$tmp"; exit 1; }; \
	  diff -r "$$tmp/$(call ent_pair,$(e))" "extracted/$(call ent_pair,$(e))" > /dev/null \
	    || { echo "check-extraction: FAIL ($(call ent_pair,$(e)) differs from a fresh extraction)"; rm -rf "$$tmp"; exit 1; }; ) \
	rm -rf "$$tmp"; \
	expected="$(foreach e,$(EXTRACTIONS),extracted/$(firstword $(subst :, ,$(e))))"; \
	for d in extracted/*/*; do \
	  case " $$expected " in *" $$d "*) ;; \
	    *) echo "check-extraction: FAIL ($$d is not a pair in EXTRACTIONS)"; exit 1;; \
	  esac; \
	done; echo "check-extraction: PASS ($(words $(EXTRACTIONS)) pairs, $(words $(foreach p,$(CORE_PAIRS),$(CORE_SETS))) per-set models)"

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
# `check` and `check-inventory` check, apart from the scans and the
# constant check, which CI runs without EasyCrypt:
#
#   sphincs       the imported SPHINCS+ proof (check-formosa)
#   crypto-specs  the imported crypto-specs theories (check-imported)
#   spec          this project's specification and security theories
#                 (check-own)
#   <arch>-<variant>  the correctness proofs against one pair's models
#                 (check-pair), for each pair of EXTRACTIONS
#   inventory     the inventory of every pair (inventory-pair), J pairs at
#                 once
#   <arch>-<variant>-<group>  the per-set proofs against the models of
#                 the sets of one group of SET_GROUPS (check-set), each
#                 with its inventory, for each pair of CORE_PAIRS
#   extraction    the committed models against a fresh extraction
#
# Every .ec and .eca file under this directory and ../third_party belongs
# to exactly one shard, except the shared correctness proofs, which a pair
# shard of each architecture checks, and the per-set proofs, which every
# group shard of their hash family checks (`shard-files`; CI checks this).
# The shards of the pairs and of the groups are those names with the `/`
# of the pair written `-`.

shard_name     = $(subst /,-,$(1))
PAIR_SHARDS    = $(foreach p,$(PAIRS),$(call shard_name,$(p)))
SET_SHARDS     = $(foreach p,$(CORE_PAIRS),$(foreach g,$(SET_GROUPS),$(call shard_name,$(p))-$(call group_name,$(g))))
SHARDS         = sphincs crypto-specs spec $(PAIR_SHARDS) inventory $(SET_SHARDS) extraction
shard_pair     = $(strip $(foreach p,$(PAIRS),$(if $(filter $(call shard_name,$(p)),$(1)),$(p))))
set_shard_pair = $(strip $(foreach p,$(CORE_PAIRS),$(foreach g,$(SET_GROUPS),\
                   $(if $(filter $(call shard_name,$(p))-$(call group_name,$(g)),$(1)),$(p)))))
set_shard_sets = $(strip $(foreach p,$(CORE_PAIRS),$(foreach g,$(SET_GROUPS),\
                   $(if $(filter $(call shard_name,$(p))-$(call group_name,$(g)),$(1)),$(call group_sets,$(g))))))

.PHONY: list-shards shard-files check-shard
list-shards:
	@echo $(SHARDS)

# Paths from the repository root.
root_path = $(patsubst ../%,%,$(patsubst %,proofs/%,$(filter-out ../%,$(1))) $(filter ../%,$(1)))
shard-files:
	@$(foreach f,$(call root_path,$(FORMOSA_FILES)),echo "sphincs $(f)";)
	@$(foreach f,$(call root_path,$(IMPORTED_FILES)),echo "crypto-specs $(f)";)
	@$(foreach f,$(call root_path,$(OWN_FILES)),echo "spec $(f)";)
	@$(foreach p,$(PAIRS),$(foreach f,$(call root_path,$(call pair_files,$(p))),echo "$(call shard_name,$(p)) $(f)";))
	@$(foreach h,$(SET_SHARDS),$(foreach s,$(call set_shard_sets,$(h)),$(foreach f,$(call root_path,$(call set_files,$(call set_shard_pair,$(h)),$(s))),echo "$(h) $(f)";)))

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
else ifeq ($(SHARD),inventory)
	@$(MAKE) --no-print-directory -j$(J) $(addprefix inventory-check/,$(PAIRS))
	@echo "inventory: PASS $(words $(PAIRS)) pairs"
else ifneq ($(call shard_pair,$(SHARD)),)
	@$(MAKE) --no-print-directory PAIR=$(call shard_pair,$(SHARD)) check-pair
else
	@n=0; for s in $(call set_shard_sets,$(SHARD)); do \
	  $(MAKE) --no-print-directory PAIR=$(call set_shard_pair,$(SHARD)) SET=$$s check-set || exit 1; \
	  $(MAKE) --no-print-directory PAIR=$(call set_shard_pair,$(SHARD)) SET=$$s MODE=check inventory-set || exit 1; \
	  n=$$((n + 1)); \
	done; echo "check-sets $(SHARD): PASS $$n sets"
endif

# One pair's inventory check, for the inventory shard's parallel make.
inventory-check/%:
	@$(MAKE) --no-print-directory PAIR=$* MODE=check inventory-pair
