# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/checks/test-hash.mk: the hash tests, once per kernel set of the
# architecture (tools/ci/hash-sets.toml, passed in as CI_HASH_SETS,
# CI_HASH_VARS_<set>, CI_HASH_CPU_<set>): CAVP and known answers, the
# differential checks, the squeeze sweep, the fill check and the negative
# controls, each goal with parallel jobs, then the minimum counts.
#
# A kernel set whose CPU features the runner lacks fails
# (tools/ci/cpu-has.sh): the check is never reduced to fewer kernels. The
# CAVP files are fetched from NIST and checked against their pins first.

include tools/ci/mk/common.mk

ifeq ($(strip $(CI_HASH_SETS)),)
$(error CI_HASH_SETS is empty: no kernel set for $(CI_ARCH))
endif

.PHONY: ci-test-hash ci-test-hash-vectors
ci-test-hash: $(addprefix ci-test-hash-,$(CI_HASH_SETS))

ci-test-hash-vectors:
	$(MAKE) -C tests/hash vectors

ci-test-hash-%: ci-test-hash-vectors
	tools/ci/cpu-has.sh $(CI_HASH_CPU_$*)
	$(call logged,hash-$*,$(MAKE) -C tests/hash -j$(CI_JOBS) $(CI_SYNC) check $(CI_HASH_VARS_$*) && $(MAKE) -C tests/hash -j$(CI_JOBS) $(CI_SYNC) negative-control $(CI_HASH_VARS_$*) && $(MAKE) -C tests/hash -j$(CI_JOBS) $(CI_SYNC) fill-check $(CI_HASH_VARS_$*))
	$(CI_COUNTS) hash $(CI_LOGS)/hash-$*.log
