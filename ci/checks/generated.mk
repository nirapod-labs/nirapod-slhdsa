# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/generated.mk: the shipped gen/ against a regeneration with
# the pinned compiler, byte for byte (`make gen-check`), so a change to the
# Jasmin sources without gen/ regenerated fails here. Then the build a user
# without the compiler makes: the library and `make check` from gen/ alone,
# JASMINC empty, in a build directory of its own.

include ci/mk/common.mk

CI_GEN_BUILD := build/gen-only

.PHONY: ci-generated
ci-generated:
	$(CI_NEED_JASMINC)
	$(MAKE) gen-check $(CI_CORE_VARS)
	rm -rf $(CI_GEN_BUILD)
	$(MAKE) check JASMINC= BUILD=$(CI_GEN_BUILD)
