# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# Appended after an upstream Makefile to read one of its variables, e.g.
#   make -s -f Makefile -f print-var.mk print-CFLAGS PARAMS=...
# so the harness builds baselines with their own flags and source lists.

print-%:
	@echo '$($*)'
