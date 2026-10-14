# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/mk/common.mk
# ===============
#
# Shared by every recipe under ci/checks/, and the only file a recipe
# includes (the source check enforces that), so that a recipe's text is an
# input of its own check alone (ci/key.py). The top-level Makefile, which
# includes */*.mk and */*/*.mk, leaves ci/ out, so it includes neither this
# file nor the recipes.
#
# ci/check.py runs a recipe with the parameters of its platform:
#
#   CI_PLATFORM  linux-x86_64, linux-aarch64 or macos-aarch64
#   CI_TARGET    the top-level Makefile's target directory, <arch>-<format>
#   CI_ARCH      x86_64 or aarch64
#   CI_JOBS      parallel jobs
#   CI_RULES     the check's minimum counts, ci/rules/<check>.toml
#
# A recipe only runs builds and tests in order; whether counts are reached
# is decided by ci/counts.py, whether the check applies at all by
# ci/check.py before the recipe starts.

CI_REQUIRED_VARS := CI_PLATFORM CI_TARGET CI_ARCH CI_JOBS CI_RULES
$(foreach v,$(CI_REQUIRED_VARS),$(if $($(v)),,$(error $(v) is not set; run the check with ci/check.py)))

CI_PYTHON ?= python3
CI_COUNTS := $(CI_PYTHON) -I ci/counts.py $(CI_RULES)
CI_OUT    := build/ci
CI_LOGS   := $(CI_OUT)/logs

# The top-level Makefile builds the library from the shipped gen/ when
# JASMINC is empty; CI checks the compiler's own output, so every core
# sub-make gets JASMINC explicitly, from the PATH.
CI_JASMINC   := $(shell command -v jasminc 2>/dev/null)
CI_CORE_VARS := JASMINC=$(CI_JASMINC)
# A recipe line that stops the recipe when jasminc is not on the PATH.
CI_NEED_JASMINC = $(if $(CI_JASMINC),@:,$(error jasminc is not on PATH))

# Output-sync where make has it (GNU make 4), so that parallel jobs do not
# interleave their lines.
CI_SYNC := $(if $(filter output-sync,$(.FEATURES)),-Otarget)

# logged(name, command): run command with its output in $(CI_LOGS)/name.log,
# print the log, keep the command's status.
logged = @mkdir -p $(CI_LOGS); echo "+ $(2)"; { $(2); } > $(CI_LOGS)/$(1).log 2>&1; rc=$$?; cat $(CI_LOGS)/$(1).log; exit $$rc
