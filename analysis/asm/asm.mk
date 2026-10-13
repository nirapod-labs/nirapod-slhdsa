# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# analysis/asm/asm.mk
# ===================
#
# Policy checks on the emitted assembly of every unit of this target
# (analysis/asm/check-asm.sh):
#
#     make asm-policy [JASMINC=...]
#
# The assembly is the one the library is built from: compiled here with
# JASMINC (or taken from gen/<target>/ where `make gen` has written it).
# Every rule also has a negative control, which must be rejected by that
# rule (analysis/asm/check-controls.sh), or the target fails.

.PHONY: asm-policy
asm-policy: $(addprefix $(ASM_DIR)/,$(addsuffix .s,$(UNITS)))
	sh analysis/asm/check-asm.sh $(ARCH) $^
	@mkdir -p $(OUT)/asm-policy
	sh analysis/asm/check-controls.sh $(ARCH) $(OUT)/asm-policy
	@echo "asm-policy: PASS for $(words $^) units ($(TARGET)); every control rejected by its rule"
