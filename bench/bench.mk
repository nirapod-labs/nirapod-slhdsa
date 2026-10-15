# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/bench.mk
# ==============
#
# Fragment of the top-level Makefile: `make bench` builds the library, then
# runs bench/run.py, which builds one benchmark program per implementation
# and writes its record to build/<target>/bench.json:
#
#     make bench JASMINC=<jasminc> BASELINES=<workdir> \
#         [BENCH_ARGS="--sets=... --rounds=..."]
#
# <workdir> is prepared by bench/baselines.py fetch and build. Without
# BASELINES only this library is measured. JASMINC reaches bench/run.py
# through the environment, and the record holds the compiler binary's
# SHA-256. docs/BENCHMARKS.md describes the method and the conditions a
# measurement needs; `python3 -I bench/run.py --help` lists BENCH_ARGS.

BENCH_ARGS ?=

.PHONY: bench
bench: lib
	python3 -I bench/run.py $(if $(BASELINES),--baselines=$(BASELINES)) \
	    --out=$(OUT)/bench.json $(BENCH_ARGS)
