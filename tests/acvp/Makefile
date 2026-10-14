# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/acvp/Makefile
# ===================
#
# ACVP runner against one implementation; IMPL and BASELINES are described
# in tests/diff/adapters/adapters.mk.
#
#   make -C tests/acvp            build the runner
#   make -C tests/acvp vectors    fetch and verify the pinned vectors, and
#                                 convert them
#   make -C tests/acvp check      the same, then run every case; fails
#                                 unless the verdict is PASS
#   make -C tests/acvp controls   run the negative controls of controls.py
#
# The runner's verdict rules are checked with two runners, one built with
# IMPL=stub (tests/acvp/verdicts.py says how).
#
# RUNNER_FLAGS passes options such as --variant=V or --sets=A,B to the
# runner. Vector files go to build/vectors/acvp (JSON, as fetched) and
# build/vectors/acvp-flat (converted); fetching needs network access the
# first time and only verifies afterwards.

PROG := acvp_runner
HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROG_SRC := $(HERE)acvp_runner.c
include $(HERE)../diff/adapters/adapters.mk

VECTORS ?= $(ROOT)/build/vectors/acvp
FLAT ?= $(ROOT)/build/vectors/acvp-flat
PYTHON ?= python3

.PHONY: vectors check controls
vectors:
	$(PYTHON) -I $(ROOT)/tests/vectors/fetch-acvp.py $(VECTORS)
	$(PYTHON) -I $(HERE)convert.py $(VECTORS) $(FLAT)

check: $(TARGET) vectors
	$(TARGET) $(RUNNER_FLAGS) $(FLAT)/keyGen.txt $(FLAT)/sigGen.txt $(FLAT)/sigVer.txt

controls: $(TARGET) vectors
	$(PYTHON) -I $(HERE)controls.py $(TARGET) $(FLAT) $(VECTORS) $(RUNNER_FLAGS)
