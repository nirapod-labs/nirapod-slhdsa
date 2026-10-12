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
- Regenerate checked-in generated files with the documented command rather
  than editing them by hand.
- New files start with the SPDX header used throughout the repository.

## Sign-off

Contributions are accepted under the Apache License 2.0. We use the
[Developer Certificate of Origin](https://developercertificate.org/) and no
CLA. Add a `Signed-off-by` line to every commit (`git commit -s`) to certify
that you wrote the change or otherwise have the right to submit it.
