- `make bench`: an end-to-end benchmark of key generation, hedged and
  deterministic signing and verification through the public API, for all
  twelve sets, against pinned baselines (slhdsa-c, the SPHINCS+ FIPS 205
  branch, OpenSSL 3.6 and 4.0, wolfSSL, BoringSSL). It reports latency
  ratios with a sign-test interval, throughput, stack use and code size,
  and records the revisions, builds and host that produced them.
  `docs/BENCHMARKS.md` describes the method; no results are published yet.
