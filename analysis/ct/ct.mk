# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# analysis/ct/ct.mk
# =================
#
# Constant-time and speculative constant-time type checks of every
# parameter-set unit, with the checker of the same Jasmin build:
#
#     make ct     jasmin-ct and jasmin-ct --sct on each unit of this target
#
# Each unit is checked with its export annotations (src/slhdsa/
# api.jinc), at the default stage (after typing), for the host's
# architecture. A check that fails, or any checker error, fails the target.
# Results are written to build/<target>/ct/<unit>.{ct,sct}.log.
#
# What a PASS establishes and what it does not is described in
# analysis/README.md: the type systems assume program safety, which no
# tool checks yet ("Memory safety" there), and they say nothing about
# declassified values beyond the type escape itself.

# The kernels of each unit's variant come from JASMIN_INCLUDES, keyed on
# the unit name (Makefile, "Kernel roots"), as for the assembly.
CT_UNITS := $(addprefix $(OUT)/ct/,$(UNITS))

$(OUT)/ct/%.ok: $(OUT)/units/%.jazz $(JASMIN_DEPS)
	@mkdir -p $(@D)
	$(JASMIN_CT) --arch $(JASMIN_ARCH) $(JASMIN_INCLUDES) $< > $(OUT)/ct/$*.ct.log 2>&1
	$(JASMIN_CT) --arch $(JASMIN_ARCH) --sct $(JASMIN_INCLUDES) $< > $(OUT)/ct/$*.sct.log 2>&1
	@touch $@

.PHONY: ct
ct: $(addsuffix .ok,$(CT_UNITS))
	@echo "ct: jasmin-ct and jasmin-ct --sct PASS for $(words $(UNITS)) units ($(TARGET))"
