# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/test-core.mk: `make check` of the library (core, negative,
# ABI, register, stack and fault tests, the ACVP subset), with every
# variant of the architecture required (--require-variants), then the core
# transcript for agree: its line count is a coverage minimum here, its
# content is compared across the platforms.

include ci/mk/common.mk

# The CPU features the variants of each architecture need on the runner,
# so that a variant that cannot run fails with the reason. On AArch64,
# sha512 implies the SHA-256 instructions (FEAT_SHA512 needs FEAT_SHA256).
CI_CORE_CPU_x86_64  := avx2 sha_ni
CI_CORE_CPU_aarch64 := sha512 sha3
CI_CORE_TRANSCRIPT  := build/$(CI_TARGET)/transcript-core.txt

.PHONY: ci-test-core
ci-test-core:
	$(CI_NEED_JASMINC)
	ci/cpu-has.sh $(CI_CORE_CPU_$(CI_ARCH))
	rm -f $(CI_CORE_TRANSCRIPT)
	$(MAKE) check $(CI_CORE_VARS) TEST_CORE_FLAGS=--require-variants
	$(CI_COUNTS) transcript $(CI_CORE_TRANSCRIPT)
	mkdir -p $(CI_OUT)
	cp $(CI_CORE_TRANSCRIPT) $(CI_OUT)/transcript-$(CI_TARGET).txt
