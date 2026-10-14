# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/checks/differential.mk: the library against slhdsa-c (PQ Code
# Package), a portable C implementation that shares no code with this one,
# fetched and checked by bench/baselines.sh against the pins of
# bench/baselines.lock: every set, every one of the 28 interface
# combinations once; then the negative control, which must report
# mismatches and exit 1 (both checked by the rules).

include tools/ci/mk/common.mk

CI_BASELINES      := $(abspath build/baselines)
CI_DIFF_SEED      ?= 20261012
CI_ORACLE_NIRAPOD := build/harness/nirapod-$(CI_TARGET)/oracle
CI_ORACLE_OTHER   := build/harness/slhdsa-c/oracle
CI_DIFFTEST = $(CI_PYTHON) -I tests/diff/difftest.py --a=$(CI_ORACLE_NIRAPOD) --b=$(CI_ORACLE_OTHER) \
              --seed=$(CI_DIFF_SEED) --sets=all

.PHONY: ci-differential
ci-differential:
	$(CI_NEED_JASMINC)
	bench/baselines.sh fetch $(CI_BASELINES)
	$(MAKE) lib $(CI_CORE_VARS)
	$(MAKE) -C tests/diff IMPL=nirapod
	$(MAKE) -C tests/diff IMPL=slhdsa-c BASELINES=$(CI_BASELINES)
	$(call logged,diff,$(CI_DIFFTEST) --count=28)
	$(CI_COUNTS) diff $(CI_LOGS)/diff.log
	@mkdir -p $(CI_LOGS); $(CI_DIFFTEST) --count=1 --control=corrupt-b > $(CI_LOGS)/diff-control.log 2>&1; \
	echo "difftest-control-exit: $$?" >> $(CI_LOGS)/diff-control.log; cat $(CI_LOGS)/diff-control.log
	$(CI_COUNTS) diff-control $(CI_LOGS)/diff-control.log
