# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/test-acvp.mk: the NIST ACVP vectors (fetched and checked
# against their pins) on the variant the library dispatches to on this CPU,
# every case of the three modes; the other variants are tied to it byte for
# byte by the core tests. Then the runner's verdict rules against a stub
# implementation (tests/acvp/verdicts.py) and the negative controls of the
# vector pipeline (tests/acvp/controls.py), each of which must detect its
# break.

include ci/mk/common.mk

# The runner must have every variant's features (as in test-core.mk), so
# that the vectors run on the accelerated variant, never on scalar alone.
CI_CORE_CPU_x86_64  := avx2 sha_ni
CI_CORE_CPU_aarch64 := sha512 sha3

.PHONY: ci-test-acvp
ci-test-acvp:
	$(CI_NEED_JASMINC)
	ci/cpu-has.sh $(CI_CORE_CPU_$(CI_ARCH))
	$(MAKE) -C tests/acvp vectors IMPL=nirapod
	$(MAKE) lib $(CI_CORE_VARS)
	$(call logged,acvp,$(MAKE) -C tests/acvp check IMPL=nirapod)
	$(CI_COUNTS) acvp $(CI_LOGS)/acvp.log
	$(MAKE) -C tests/acvp IMPL=stub
	$(CI_PYTHON) -I tests/acvp/verdicts.py build/harness/stub/acvp_runner \
	  build/harness/nirapod-$(CI_TARGET)/acvp_runner build/vectors/acvp-flat
	$(MAKE) -C tests/acvp controls IMPL=nirapod
