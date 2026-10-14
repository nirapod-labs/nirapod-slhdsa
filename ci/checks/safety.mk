# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/checks/safety.mk: jasmin-checksafety on every export (`make
# safety`, analysis/safety). Until that component lands the check is NOT
# RUN, decided from the tree (tools/ci/checks.toml), and this recipe does
# not run.

include tools/ci/mk/common.mk

.PHONY: ci-safety
ci-safety:
	$(CI_NEED_JASMINC)
	$(MAKE) safety $(CI_CORE_VARS)
