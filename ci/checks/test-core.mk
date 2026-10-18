# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/test-core.mk: `make check` of the library (core, negative,
# ABI, register, stack and fault tests, the ACVP subset), with every
# variant of the architecture required (--require-variants), then the core
# transcript for agree: its line count is a coverage minimum here, its
# content is compared across the platforms. Then the fill check (make
# fill-check), whose site count the rules hold, and on one platform its
# controls (make fill-check-controls): one build per filled buffer, eleven
# library builds, so not repeated on every platform. They fail if the
# fill check ever stops building from the rewritten sources.

include ci/mk/common.mk

# The CPU features the variants of each architecture need on the runner,
# so that a variant that cannot run fails with the reason. On AArch64,
# sha512 implies the SHA-256 instructions (FEAT_SHA512 needs FEAT_SHA256).
CI_CORE_CPU_x86_64  := avx2 sha_ni
CI_CORE_CPU_aarch64 := sha512 sha3
CI_CORE_TRANSCRIPT  := build/$(CI_TARGET)/transcript-core.txt
CI_FILL_CONTROLS_linux-aarch64 := yes

.PHONY: ci-test-core
ci-test-core:
	$(CI_NEED_JASMINC)
	ci/cpu-has.sh $(CI_CORE_CPU_$(CI_ARCH))
	rm -f $(CI_CORE_TRANSCRIPT)
	$(MAKE) check $(CI_CORE_VARS) TEST_CORE_FLAGS=--require-variants
	$(CI_COUNTS) transcript $(CI_CORE_TRANSCRIPT)
	mkdir -p $(CI_OUT)
	cp $(CI_CORE_TRANSCRIPT) $(CI_OUT)/transcript-$(CI_TARGET).txt
	$(call logged,fill-check,$(MAKE) fill-check $(CI_CORE_VARS) TEST_CORE_FLAGS=--require-variants)
	$(CI_COUNTS) fill-check $(CI_LOGS)/fill-check.log
	$(if $(CI_FILL_CONTROLS_$(CI_PLATFORM)),$(call logged,fill-controls,$(MAKE) fill-check-controls $(CI_CORE_VARS) FILL_JOBS=$(CI_JOBS)),@echo "fill-check controls: run on linux-aarch64 only")
	$(if $(CI_FILL_CONTROLS_$(CI_PLATFORM)),$(CI_COUNTS) fill-controls $(CI_LOGS)/fill-controls.log,@:)
