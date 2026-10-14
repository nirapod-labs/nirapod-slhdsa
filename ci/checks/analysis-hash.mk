# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/analysis-hash.mk: jasmin-ct and jasmin-ct --sct on the
# hash test exports, once per kernel set of the architecture
# (ci/hash-sets.toml).

include ci/mk/common.mk

ifeq ($(strip $(CI_HASH_SETS)),)
$(error CI_HASH_SETS is empty: no kernel set for $(CI_ARCH))
endif

.PHONY: ci-analysis-hash
ci-analysis-hash: $(addprefix ci-analysis-hash-,$(CI_HASH_SETS))

ci-analysis-hash-%:
	$(MAKE) -C tests/hash ct sct $(CI_HASH_VARS_$*)
