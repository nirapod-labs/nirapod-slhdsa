# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/differential.mk: the library against slhdsa-c (PQ Code
# Package), a portable C implementation that shares no code with this one,
# fetched and checked by bench/baselines.py against its pin in
# bench/baselines.lock: every set, every one of the 28 interface
# combinations once (tests/diff/difftest.py). Then two controls: the
# driver's own verdict rules against a stub oracle (tests/diff/controls.py),
# and a corrupted second implementation, which must report mismatches and
# exit 1 (both checked by the rules).

include ci/mk/common.mk

CI_BASELINES      := $(abspath build/baselines)
CI_DIFF_SEED      ?= 20261012
CI_ORACLE_NIRAPOD := build/harness/nirapod-$(CI_TARGET)/oracle
CI_ORACLE_OTHER   := build/harness/slhdsa-c/oracle
CI_ORACLE_STUB    := build/harness/stub/oracle
CI_DIFFTEST = $(CI_PYTHON) -I tests/diff/difftest.py --a=$(CI_ORACLE_NIRAPOD) --b=$(CI_ORACLE_OTHER) \
              --seed=$(CI_DIFF_SEED) --sets=all

.PHONY: ci-differential
ci-differential:
	$(CI_NEED_JASMINC)
	$(CI_PYTHON) -I bench/baselines.py fetch $(CI_BASELINES) slhdsa-c
	$(MAKE) lib $(CI_CORE_VARS)
	$(MAKE) -C tests/diff IMPL=nirapod
	$(MAKE) -C tests/diff IMPL=slhdsa-c BASELINES=$(CI_BASELINES)
	$(MAKE) -C tests/diff IMPL=stub
	$(call logged,diff,$(CI_DIFFTEST) --count=28)
	$(CI_COUNTS) diff $(CI_LOGS)/diff.log
	$(CI_PYTHON) -I tests/diff/controls.py $(CI_ORACLE_STUB) $(CI_ORACLE_NIRAPOD) $(CI_ORACLE_OTHER)
	@mkdir -p $(CI_LOGS); $(CI_DIFFTEST) --count=1 --control=corrupt-b > $(CI_LOGS)/diff-control.log 2>&1; \
	echo "difftest-control-exit: $$?" >> $(CI_LOGS)/diff-control.log; cat $(CI_LOGS)/diff-control.log
	$(CI_COUNTS) diff-control $(CI_LOGS)/diff-control.log
