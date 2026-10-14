# Unreleased changes

Each change that users can notice is described in a file of its own here,
so that pull requests merged in parallel never edit the same lines of
`CHANGELOG.md`. A release collects the files into its section of
`CHANGELOG.md` and removes them.

## Adding an entry

1. Pick the directory for the kind of change: `added`, `changed`, `fixed`
   or `security` (create it if it does not exist yet).
2. Name the file `<pull request number>-<slug>.md`, for example
   `fixed/42-wots-chain-bound.md`. The slug is lower-case letters, digits
   and hyphens. Open the pull request first if you need its number.
3. Write one or more Markdown list items, in the style of `CHANGELOG.md`:
   what changed for a user, and any limitation they need to know.

   ```markdown
   - `slhdsa_sign` rejects a context string longer than 255 bytes with
     `SLHDSA_ERR_CONTEXT` instead of truncating it.
   ```

   Leave out the link to the pull request. The release adds it to each
   item from the number in the file name, before the final full stop:

   ```markdown
   - `slhdsa_sign` rejects a context string longer than 255 bytes with
     `SLHDSA_ERR_CONTEXT` instead of truncating it
     ([PR #42](https://github.com/nirapod-labs/nirapod-slhdsa/pull/42)).
   ```

   An entry that already links to a pull request of this repository fails
   the check.

CI asks for an entry when a pull request changes `src/`, `toolchain/`,
`proofs/`, `third_party/`, `analysis/`, `include/`, the top-level
`Makefile` or a `*.mk` file. A change with nothing to tell users, such as
a comment fix, carries the label `no-changelog` instead.

## Releasing

`ci/changes.sh section vX.Y.Z YYYY-MM-DD` prints the section the
entries make. `ci/changes.sh release vX.Y.Z YYYY-MM-DD` writes it into
`CHANGELOG.md` and removes the entries; that is the release commit, made
before the tag.
