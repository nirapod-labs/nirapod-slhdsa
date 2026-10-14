# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# adapters.mk
# ===========
#
# Shared by tests/acvp/Makefile and tests/diff/Makefile.
# Selects one implementation behind tests/diff/adapters/impl.h and defines
# how a harness program is linked against it:
#
#   IMPL=slhdsa-c     BASELINES=<workdir>
#   IMPL=nirapod      [NIRAPOD_ROOT=<tree with the library built>]
#   IMPL=stub         fake implementation for the drivers' verdict-rule checks
#
# <workdir> is the directory prepared by bench/baselines.py. Each baseline is
# compiled with its own project's compiler and flags, read from its own
# Makefile, so it is tested as its authors build it. Harness sources use
# HARNESS_CFLAGS.
#
# The including Makefile sets PROG (output name) and PROG_SRC (its main
# source) and then uses the rule defined at the end.

ADAPTERS := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ROOT := $(abspath $(ADAPTERS)/../../..)
BUILD ?= $(ROOT)/build/harness
IMPL ?= slhdsa-c
CC ?= cc
HARNESS_CFLAGS ?= -O2 -std=c99 -Wall -Wextra
PRINT = $(MAKE) -s --no-print-directory -f Makefile -f $(ADAPTERS)/print-var.mk
TABLES := $(ADAPTERS)/tables.c
HDR := $(ADAPTERS)/impl.h

ifeq ($(shell uname -s),Linux)
SYSLIBS := -lpthread -ldl
else
SYSLIBS := -lpthread
endif

ifeq ($(filter nirapod stub,$(IMPL)),)
ifndef BASELINES
$(error BASELINES must name the directory prepared by bench/baselines.py)
endif
endif

ifeq ($(IMPL),slhdsa-c)
TAG := slhdsa-c
UP_DIR := $(BASELINES)/src/slhdsa-c
UP_CC := $(shell cd $(UP_DIR) && $(PRINT) print-CC)
UP_CFLAGS := $(shell cd $(UP_DIR) && $(PRINT) print-CFLAGS)
OBJDIR := $(BUILD)/$(TAG)/obj
UP_OBJS := $(patsubst $(UP_DIR)/%.c,$(OBJDIR)/%.o,$(wildcard $(UP_DIR)/*.c))
ADAPTER := $(ADAPTERS)/impl_slhdsa_c.c
ADAPTER_INC := -I$(UP_DIR)
LINK_IN := $(UP_OBJS)

$(OBJDIR)/%.o: $(UP_DIR)/%.c $(wildcard $(UP_DIR)/*.h) $(ADAPTERS)/adapters.mk
	@mkdir -p $(@D)
	$(UP_CC) $(UP_CFLAGS) -c $< -o $@
endif

# A fake implementation for checking the drivers' verdict rules only.
ifeq ($(IMPL),stub)
TAG := stub
ADAPTER := $(ADAPTERS)/impl_stub.c
endif

# This library's testing build, made by `make lib` of the top-level
# Makefile in build/<target>/lib (impl_nirapod.c says what it adds to the
# application library). NIRAPOD_ROOT is the tree holding that build (by
# default this one); NIRAPOD_TESTING_INC is the one place the testing
# header's location is named.
ifeq ($(IMPL),nirapod)
NIRAPOD_ROOT ?= $(ROOT)
NIRAPOD_TESTING_INC ?= $(NIRAPOD_ROOT)/capi/testing
NIRAPOD_ARCH := $(if $(filter arm64 aarch64,$(shell uname -m)),aarch64,x86_64)
NIRAPOD_FORMAT := $(if $(filter Darwin,$(shell uname -s)),macho,elf)
NIRAPOD_TARGET ?= $(NIRAPOD_ARCH)-$(NIRAPOD_FORMAT)
TAG := nirapod-$(NIRAPOD_TARGET)
ADAPTER := $(ADAPTERS)/impl_nirapod.c
ADAPTER_INC := -I$(NIRAPOD_ROOT)/include -I$(NIRAPOD_TESTING_INC)
LINK_IN := $(NIRAPOD_ROOT)/build/$(NIRAPOD_TARGET)/lib/libnirapod_slhdsa_testing.a
endif

ifndef TAG
$(error unknown IMPL '$(IMPL)')
endif

OUT := $(BUILD)/$(TAG)
TARGET := $(OUT)/$(PROG)

.PHONY: all
all: $(TARGET)

$(TARGET): $(HDR) $(TABLES) $(ADAPTER) $(LINK_IN) $(PROG_SRC) $(ADAPTERS)/adapters.mk
	@mkdir -p $(@D)
	$(CC) $(HARNESS_CFLAGS) -I$(ADAPTERS) $(ADAPTER_INC) -o $@ \
	    $(PROG_SRC) $(TABLES) $(ADAPTER) $(LINK_IN) $(LINK_LIBS) $(SYSLIBS)
