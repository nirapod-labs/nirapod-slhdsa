# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/Makefile
# ==============
#
# Builds the benchmark program (bench.c) against one implementation:
#
#   make -C bench IMPL=nirapod            this library, application library
#                                         and public API (backend_public.c)
#   make -C bench IMPL=nirapod-testing    this library, testing library
#                                         (backend_testing.c)
#   make -C bench IMPL=<baseline> BASELINES=<workdir> [...]
#                                         a baseline through its adapter
#                                         (backend_adapter.c); IMPL and the
#                                         other variables as described in
#                                         tests/diff/adapters/adapters.mk
#
# The two builds of this library need `make lib` first. Programs are
# written to build/bench/<tag>/bench; `make -s -C bench IMPL=... print-TARGET`
# names the one a configuration builds, and print-<VAR> any other variable,
# which bench/run.py uses to record compilers and flags.
#
# Every program is compiled with BENCH_CFLAGS (default -O2), except with
# sphincsplus, which adapters.mk compiles in one call with that project's
# own flags. The library itself is built with the top-level Makefile's
# flags; bench/run.py records both.

.DEFAULT_GOAL := all
PROG := bench
BENCH_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BENCH_ROOT := $(abspath $(BENCH_DIR)/..)
BUILD ?= $(BENCH_ROOT)/build/bench
CC ?= cc
BENCH_CFLAGS ?= -O2
HARNESS_CFLAGS := $(BENCH_CFLAGS) -std=c99 -Wall -Wextra
DRIVER := $(BENCH_DIR)/bench.c $(BENCH_DIR)/backend.h

NIRAPOD_ARCH := $(if $(filter arm64 aarch64,$(shell uname -m)),aarch64,x86_64)
NIRAPOD_FORMAT := $(if $(filter Darwin,$(shell uname -s)),macho,elf)
NIRAPOD_TARGET ?= $(NIRAPOD_ARCH)-$(NIRAPOD_FORMAT)
NIRAPOD_LIBDIR := $(BENCH_ROOT)/build/$(NIRAPOD_TARGET)/lib

ifeq ($(IMPL),nirapod)
TAG := nirapod-$(NIRAPOD_TARGET)
LINK_IN := $(NIRAPOD_LIBDIR)/libnirapod_slhdsa.a
BACKEND := $(BENCH_DIR)/backend_public.c
BACKEND_INC := -I$(BENCH_ROOT)/include
else ifeq ($(IMPL),nirapod-testing)
TAG := nirapod-testing-$(NIRAPOD_TARGET)
LINK_IN := $(NIRAPOD_LIBDIR)/libnirapod_slhdsa_testing.a
BACKEND := $(BENCH_DIR)/backend_testing.c
BACKEND_INC := -I$(BENCH_ROOT)/include -I$(BENCH_ROOT)/capi/testing
endif

ifdef BACKEND
TARGET := $(BUILD)/$(TAG)/$(PROG)

.PHONY: all
all: $(TARGET)

$(TARGET): $(DRIVER) $(BACKEND) $(LINK_IN) $(BENCH_DIR)/Makefile
	@mkdir -p $(@D)
	$(CC) $(HARNESS_CFLAGS) $(BACKEND_INC) -o $@ $(BENCH_DIR)/bench.c $(BACKEND) $(LINK_IN) \
	    -lpthread
else
# A baseline: the adapter build of tests/diff, with this driver and backend
# as the program. BoringSSL signs hedged only with its own randomness
# (backend_adapter.c).
PROG_SRC := $(BENCH_DIR)/bench.c $(BENCH_DIR)/backend_adapter.c
ifeq ($(IMPL),boringssl)
PROG_SRC += $(BENCH_DIR)/hedged_boringssl.c
HARNESS_CFLAGS += -DBENCH_HEDGED_OWN
endif
include $(BENCH_ROOT)/tests/diff/adapters/adapters.mk
# adapters.mk lists PROG_SRC only; the driver's header and this file are
# inputs of every program too.
ifdef TARGET
$(TARGET): $(BENCH_DIR)/backend.h $(BENCH_DIR)/Makefile
endif
endif

print-%:
	@echo '$($*)'
