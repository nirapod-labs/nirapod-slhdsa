# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# tools/ci/checks/proofs.mk: one shard of the EasyCrypt development
# (CI_SHARD; proofs/Makefile, check-shard), its files checked in parallel,
# then the shard's minimum counts. Run inside the opam switch
# (tools/ci/toolchain.sh exec), for EasyCrypt and the provers.

include tools/ci/mk/common.mk

ifeq ($(strip $(CI_SHARD)),)
$(error CI_SHARD is not set)
endif

.PHONY: ci-proofs
ci-proofs:
	$(call logged,proofs-$(CI_SHARD),$(MAKE) -C proofs check-shard SHARD=$(CI_SHARD) J=$(CI_JOBS))
	$(CI_COUNTS) $(CI_SHARD) $(CI_LOGS)/proofs-$(CI_SHARD).log
