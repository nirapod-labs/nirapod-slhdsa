- `nirapod_slhdsa.h` states the version with `NIRAPOD_SLHDSA_VERSION_MAJOR`,
  `NIRAPOD_SLHDSA_VERSION_MINOR`, `NIRAPOD_SLHDSA_VERSION_PATCH` and
  `NIRAPOD_SLHDSA_VERSION_STRING`, set to 0.1.0. They are macros only: the
  library exports no new symbol. CI fails when they disagree with the
  `version` of `CITATION.cff` or the newest release heading of
  `CHANGELOG.md`, and, for a release tag, when the tag is not `v` and that
  version or the changelog has no section for it.
- CI runs on the push of a `v*` tag, every check in full, reusing no result
  of an earlier run.
- `CITATION.cff` gives the version and an abstract, and `SECURITY.md` lists
  the supported versions.
