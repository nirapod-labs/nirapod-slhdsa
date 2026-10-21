# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/test-acvp-scalar.mk: the NIST ACVP vectors (fetched and checked
# against their pins) with the scalar variant forced for every set, every
# case of the three modes. The scalar exports are the ones the correctness
# proofs cover, and no CI runner selects them on its own, so test-acvp
# never runs them; this run is what docs/PROOFS.md calls testing the
# specification through the code. The rules pin the forced variant and the
# counts: a run on another variant, or with a set or a group left out,
# fails. The runner's verdict rules and the controls of the vector pipeline
# do not depend on the variant and stay with test-acvp.

include ci/mk/common.mk

.PHONY: ci-test-acvp-scalar
ci-test-acvp-scalar:
	$(CI_NEED_JASMINC)
	$(MAKE) -C tests/acvp vectors IMPL=nirapod
	$(MAKE) lib $(CI_CORE_VARS)
	$(call logged,acvp-scalar,$(MAKE) -C tests/acvp check IMPL=nirapod RUNNER_FLAGS=--variant=scalar)
	$(CI_COUNTS) acvp $(CI_LOGS)/acvp-scalar.log
