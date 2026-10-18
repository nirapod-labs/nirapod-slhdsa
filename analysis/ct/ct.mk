# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# analysis/ct/ct.mk
# =================
#
# Constant-time and speculative constant-time type checks of every
# parameter-set unit, with the checker of the same Jasmin build:
#
#     make ct     jasmin-ct, jasmin-ct --sct and jasmin-ct --doit on each
#                 unit of this target, and the controls of --doit
#
# Each unit is checked with its export annotations (src/slhdsa/
# api.jinc), for the host's architecture. jasmin-ct and --sct run at the
# default stage (after typing). --doit admits a secret operand only in an
# instruction the compiler marks data-operand-independent (Intel DOIT,
# Arm DIT). jasmin-ct runs --doit after instruction selection at the
# earliest, whatever stage is asked for; slhlowering is later, so the
# speculation operators are checked as the instructions they become. The
# AArch64 control, a #protect on a secret, passes at the lowering stage,
# where the operator is still a pseudo-instruction the compiler marks,
# and fails here. The next stage, loweraddr, stops on an assertion inside
# jasmin-ct for these units. The passes after slhlowering are not seen
# (analysis/README.md says what covers them). Moves, loads and stores are
# outside its policy.
# A check that fails, or any checker error, fails the target. Results are
# written to build/<target>/ct/<unit>.{ct,sct,doit}.log.
#
# The controls (analysis/ct/controls/doit-<arch>.jazz) each give a
# secret to one instruction the compiler does not mark: jasmin-ct must
# accept the file and jasmin-ct --doit must reject it, or the target
# fails. Their logs go to build/<target>/ct-controls/.
#
# What a PASS establishes and what it does not is described in
# analysis/README.md: the type systems assume program safety, which no
# tool checks yet ("Memory safety" there), and they say nothing about
# declassified values beyond the type escape itself.

# The kernels of each unit's variant come from JASMIN_INCLUDES, keyed on
# the unit name (Makefile, "Kernel roots"), as for the assembly.
CT_UNITS := $(addprefix $(OUT)/ct/,$(UNITS))

# The pass after which --doit runs (jasmin-ct --compile).
CT_DOIT_STAGE := slhlowering

$(OUT)/ct/%.ok: $(OUT)/units/%.jazz $(JASMIN_DEPS)
	@mkdir -p $(@D)
	$(JASMIN_CT) --arch $(JASMIN_ARCH) $(JASMIN_INCLUDES) $< > $(OUT)/ct/$*.ct.log 2>&1
	$(JASMIN_CT) --arch $(JASMIN_ARCH) --sct $(JASMIN_INCLUDES) $< > $(OUT)/ct/$*.sct.log 2>&1
	$(JASMIN_CT) --arch $(JASMIN_ARCH) --doit --compile=$(CT_DOIT_STAGE) $(JASMIN_INCLUDES) $< > $(OUT)/ct/$*.doit.log 2>&1
	@touch $@

CT_DOIT_CONTROL := analysis/ct/controls/doit-$(ARCH).jazz

.PHONY: ct-controls
ct-controls: $(CT_DOIT_CONTROL)
	@mkdir -p $(OUT)/ct-controls
	$(JASMIN_CT) --arch $(JASMIN_ARCH) --compile=$(CT_DOIT_STAGE) $< > $(OUT)/ct-controls/doit.ct.log 2>&1
	@if $(JASMIN_CT) --arch $(JASMIN_ARCH) --doit --compile=$(CT_DOIT_STAGE) $< > $(OUT)/ct-controls/doit.log 2>&1; then \
	  echo "ct-controls: jasmin-ct --doit accepted $<" >&2; exit 1; \
	elif ! grep -q 'has type secret it needs to be public' $(OUT)/ct-controls/doit.log; then \
	  echo "ct-controls: jasmin-ct --doit rejected $< for another reason:" >&2; \
	  cat $(OUT)/ct-controls/doit.log >&2; exit 1; \
	fi

.PHONY: ct
ct: $(addsuffix .ok,$(CT_UNITS)) ct-controls
	@echo "ct: jasmin-ct, --sct and --doit PASS for $(words $(UNITS)) units ($(TARGET)); --doit control rejected"
