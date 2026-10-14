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
#   IMPL=openssl      BASELINES=<workdir> [OPENSSL=openssl-4.0.3]
#   IMPL=wolfssl      BASELINES=<workdir> [WOLFSSL=wolfssl-5.9.4]
#   IMPL=boringssl    BASELINES=<workdir>
#   IMPL=sphincsplus  BASELINES=<workdir> SPX_VARIANT=<dir> SPX_SET=<set name>
#   IMPL=nirapod      [NIRAPOD_ROOT=<tree with the library built>]
#   IMPL=stub         fake implementation for the drivers' verdict-rule checks
#
# <workdir> is the directory prepared by bench/baselines.py. Each baseline is
# compiled with its own project's compiler and flags, read from its own
# Makefile, so it is tested as its authors build it. Harness sources use
# HARNESS_CFLAGS, except with sphincsplus, whose Makefiles link each program
# in a single -flto compiler call; the harness follows that.
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

ifeq ($(IMPL),openssl)
OPENSSL ?= openssl-4.0.3
TAG := $(OPENSSL)
PREFIX := $(BASELINES)/out/$(OPENSSL)
ADAPTER := $(ADAPTERS)/impl_openssl.c
ADAPTER_INC := -I$(PREFIX)/include
LINK_IN := $(PREFIX)/lib/libcrypto.a
endif

ifeq ($(IMPL),wolfssl)
WOLFSSL ?= wolfssl-5.9.4
TAG := $(WOLFSSL)
PREFIX := $(BASELINES)/out/$(WOLFSSL)
ADAPTER := $(ADAPTERS)/impl_wolfssl.c
ADAPTER_INC := -I$(PREFIX)/include
LINK_IN := $(PREFIX)/lib/libwolfssl.a
LINK_LIBS := -lm
endif

ifeq ($(IMPL),boringssl)
TAG := boringssl
PREFIX := $(BASELINES)/out/boringssl
ADAPTER := $(ADAPTERS)/impl_boringssl.c
ADAPTER_INC := -I$(PREFIX)/include
LINK_IN := $(PREFIX)/lib/libcrypto.a
# BoringSSL's libcrypto is C++ and needs the C++ runtime.
LINK_LIBS := $(if $(filter Darwin,$(shell uname -s)),-lc++,-lstdc++)
endif

ifeq ($(IMPL),sphincsplus)
ifndef SPX_VARIANT
$(error SPX_VARIANT is required for IMPL=sphincsplus)
endif
ifndef SPX_SET
$(error SPX_SET is required for IMPL=sphincsplus)
endif
SPX_PARAMS := sphincs-$(shell echo $(SPX_SET) | sed 's/^SLH-DSA-//' | tr A-Z a-z)
TAG := sphincsplus-$(SPX_VARIANT)-$(SPX_PARAMS)
UP_DIR := $(BASELINES)/src/sphincsplus/$(SPX_VARIANT)
UP_CC := $(shell cd $(UP_DIR) && $(PRINT) print-CC PARAMS=$(SPX_PARAMS))
UP_CFLAGS := $(shell cd $(UP_DIR) && $(PRINT) print-CFLAGS PARAMS=$(SPX_PARAMS))
UP_SOURCES := $(shell cd $(UP_DIR) && $(PRINT) print-SOURCES PARAMS=$(SPX_PARAMS))
UP_PREBUILT := $(filter %.o,$(UP_SOURCES))
ADAPTER := $(ADAPTERS)/impl_sphincsplus.c
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

ifeq ($(IMPL),sphincsplus)
# Upstream sources and headers are prerequisites, so a changed checkout rebuilds.
$(TARGET): $(HDR) $(TABLES) $(ADAPTER) $(PROG_SRC) $(ADAPTERS)/adapters.mk \
    $(addprefix $(UP_DIR)/,$(filter-out %.o,$(UP_SOURCES))) $(wildcard $(UP_DIR)/*.h)
	@mkdir -p $(@D)
	$(if $(UP_PREBUILT),cd $(UP_DIR) && $(MAKE) PARAMS=$(SPX_PARAMS) $(UP_PREBUILT))
	cd $(UP_DIR) && $(UP_CC) $(UP_CFLAGS) -I. -I$(ADAPTERS) \
	    -DSPX_SET_NAME='"$(SPX_SET)"' -DSPX_VARIANT_NAME='"$(SPX_VARIANT)"' \
	    -DSPX_FAMILY_$(if $(findstring sha2,$(SPX_PARAMS)),SHA2,SHAKE) \
	    -o $@ $(UP_SOURCES) $(TABLES) $(ADAPTER) $(PROG_SRC) $(SYSLIBS)
else
$(TARGET): $(HDR) $(TABLES) $(ADAPTER) $(LINK_IN) $(PROG_SRC) $(ADAPTERS)/adapters.mk
	@mkdir -p $(@D)
	$(CC) $(HARNESS_CFLAGS) -I$(ADAPTERS) $(ADAPTER_INC) -o $@ \
	    $(PROG_SRC) $(TABLES) $(ADAPTER) $(LINK_IN) $(LINK_LIBS) $(SYSLIBS)
endif
