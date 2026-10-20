# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/checks/memcheck.mk: `make memcheck`, the programs of `make check` that
# call the library run under Valgrind's memcheck on both libraries, the
# variants Valgrind's CPU leaves out listed, and the negative control (a
# one-byte-short heap buffer written by a Jasmin export) required to be
# reported; then the counts. Linux only. Testing evidence, kept apart from
# the safety check: it sees the paths the tests take, not every path.
#
# No --require-variants: Valgrind shows the library a CPU without the
# extensions it does not emulate, so the variants that need them are not
# selected here, and memcheck.py names them in the log.

include ci/mk/common.mk

.PHONY: ci-memcheck
ci-memcheck:
	$(CI_NEED_JASMINC)
	$(call logged,memcheck,$(MAKE) memcheck $(CI_CORE_VARS) MEMCHECK_JOBS=$(CI_JOBS))
	$(CI_COUNTS) memcheck $(CI_LOGS)/memcheck.log
