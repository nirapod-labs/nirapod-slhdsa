- A check's CI key covers what `ci/checks.toml` says about that check rather
  than the whole file, so a comment or another check's entry no longer runs
  every check again. The hash checks and the proof shards no longer depend on
  the top-level `Makefile`, which they never run.
