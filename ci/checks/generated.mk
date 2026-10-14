# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/generated.mk: the shipped gen/ against a regeneration with
# the pinned compiler, byte for byte (`make gen-check`).

include ci/mk/common.mk

.PHONY: ci-generated
ci-generated:
	$(CI_NEED_JASMINC)
	$(MAKE) gen-check $(CI_CORE_VARS)
