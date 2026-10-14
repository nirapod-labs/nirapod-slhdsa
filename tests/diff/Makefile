# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/diff/Makefile
# ===================
#
# Builds the differential oracle against one implementation; IMPL and
# BASELINES are described in tests/diff/adapters/adapters.mk. difftest.py
# drives two oracles. This library against slhdsa-c, after `make lib` and
# `python3 -I bench/baselines.py fetch <workdir> slhdsa-c`:
#
#   make -C tests/diff IMPL=nirapod
#   make -C tests/diff IMPL=slhdsa-c BASELINES=<workdir>
#   python3 -I tests/diff/difftest.py --seed=1 --sets=all \
#       --a=build/harness/nirapod-<target>/oracle --b=build/harness/slhdsa-c/oracle
#
# and the driver's own controls, with the stub:
#
#   make -C tests/diff IMPL=stub
#   python3 -I tests/diff/controls.py build/harness/stub/oracle \
#       build/harness/nirapod-<target>/oracle build/harness/slhdsa-c/oracle

PROG := oracle
HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROG_SRC := $(HERE)oracle.c
include $(HERE)adapters/adapters.mk
