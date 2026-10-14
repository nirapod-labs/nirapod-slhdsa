# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/analysis-units.mk: jasmin-ct and jasmin-ct --sct on every
# parameter-set unit of the architecture (`make ct`, analysis/ct/ct.mk).
# The records of an earlier run are removed first; the rules then require
# one of each per unit, and as many units as the architecture has.

include ci/mk/common.mk

.PHONY: ci-analysis-units
ci-analysis-units:
	rm -rf build/$(CI_TARGET)/ct
	$(MAKE) ct
	$(CI_COUNTS) ct build --target $(CI_TARGET) --arch $(CI_ARCH)
