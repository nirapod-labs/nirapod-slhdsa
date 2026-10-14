# Contributing

Thank you for your interest. Bug reports, review comments and patches are
welcome.

## Before you start

- Open an issue first for anything larger than a small fix, so the approach
  can be agreed before you spend time on it.
- Report security problems privately; see `SECURITY.md`.

## Patches

- Keep each change narrow and explain the reason in the pull request.
- A change to Jasmin source is reviewed with its effect on generated
  assembly, constant-time analysis, proofs and performance. Say which of these
  you checked and how.
- A change users can notice (to the library, its interface, the proofs or
  the toolchain) adds a file `changes/<category>/<PR number>-<slug>.md` in
  the same pull request, as `changes/README.md` describes, rather than
  editing `CHANGELOG.md`. CI asks for one when such a change has none.
- Regenerate checked-in generated files with the documented command rather
  than editing them by hand.
- New files start with the SPDX header used throughout the repository.
- In the CI tooling, shell is glue only: it installs packages, sets up the
  environment and runs steps in order. Anything that parses, computes keys
  or digests, generates files or decides whether a check passed is Python,
  standard library only, with tests under `ci/tests`. See
  `ci/README.md`.

## Sign-off

Contributions are accepted under the Apache License 2.0. We use the
[Developer Certificate of Origin](https://developercertificate.org/) and no
CLA. Add a `Signed-off-by` line to every commit (`git commit -s`) to certify
that you wrote the change or otherwise have the right to submit it.
