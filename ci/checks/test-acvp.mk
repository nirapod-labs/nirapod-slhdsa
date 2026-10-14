# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/test-acvp.mk: the NIST ACVP vectors (fetched and checked
# against their pins) on the variant the library dispatches to on this CPU,
# with the negative controls; the other variants are tied to it byte for
# byte by the core tests.

include ci/mk/common.mk

CI_CORE_CPU_x86_64  := avx2 sha_ni
CI_CORE_CPU_aarch64 :=

.PHONY: ci-test-acvp
ci-test-acvp:
	$(CI_NEED_JASMINC)
	ci/cpu-has.sh $(CI_CORE_CPU_$(CI_ARCH))
	$(MAKE) -C tests/acvp vectors IMPL=nirapod
	$(MAKE) lib $(CI_CORE_VARS)
	$(call logged,acvp,$(MAKE) -C tests/acvp check IMPL=nirapod)
	$(CI_COUNTS) acvp $(CI_LOGS)/acvp.log
	$(MAKE) -C tests/acvp controls IMPL=nirapod
