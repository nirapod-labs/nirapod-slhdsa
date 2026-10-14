# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/asm-policy.mk: the emitted-code rules on the assembly of
# every unit, and their negative controls (`make asm-policy`,
# analysis/asm/asm.mk).

include ci/mk/common.mk

.PHONY: ci-asm-policy
ci-asm-policy:
	$(CI_NEED_JASMINC)
	$(MAKE) asm-policy $(CI_CORE_VARS)
