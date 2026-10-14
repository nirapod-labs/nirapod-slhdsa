# Continuous integration

The checks a change must pass to reach `main`, and the tools that run them.
Everything here runs on GitHub's hosted runners, natively on each
supported platform, and every check also runs on a workstation with the
pinned toolchain.

## Layout

| Path | What it holds |
|---|---|
| `checks.toml` | the registry: platforms, components, every check with its platforms, toolchain and the paths it does not read |
| `checks/<recipe>.mk` | the recipe of one check (or of the proof shards): the builds and tests it runs, in order |
| `rules/<check>.toml` | the minimum case counts of one check (`counts.py`) |
| `mk/common.mk` | the parameters and helpers every recipe includes, and the only file a recipe includes |
| `hash-sets.toml` | the hash kernel sets each architecture is tested with |
| `key.py` | the key of a check: the SHA-256 of what it reads |
| `record.py`, `store.py` | records of passed checks, and the one place results of other runs are taken from |
| `plan.py`, `check.py`, `gate.py` | the plan of a run, running and recording checks, the gates |
| `toolchain.py`, `toolchain.sh` | build keys and bundles of the pinned toolchain; packages, packing, its environment |
| `source.py`, `components.py`, `kernel_roots.py` | the checks that need no toolchain; `kernel_roots.py` ties the proof models to the kernels the library builds |
| `lint.py`, `policy.py` | linters of the workflows and scripts, and the rules for the workflows |
| `changelog.py`, `retry.py`, `drift.py` | the side workflows: changelog entry, one re-run after a lost runner, upstream drift |
| `tests/` | tests of all of the above |

## Running a check

With the pinned toolchain on the `PATH` (`toolchain/build.sh`, then
`ci/toolchain.sh bin-path`), from the repository root:

```sh
python3 ci/check.py run test-hash linux-x86_64
python3 ci/key.py key test-hash linux-x86_64      # its key
python3 ci/key.py inputs test-hash linux-x86_64   # the files it reads
python3 ci/source.py                               # no toolchain needed
python3 -m unittest discover -s ci/tests           # the tests of this directory
```

## How a run decides what to run

Each check's key covers the content of every file it reads, the
toolchain's source files, the platform and the runner label (`key.py`
explains the exact definition). A check reads every tracked file except the
paths `checks.toml` lists for it, so a new file is read by every check
until someone shows that a check does not read it.

On a pull request, a check whose key has a passing record from the newest
run of `ci.yml` on `main` that ran it is reported with that record (its
run, commit and runner image) and not run again. Pushes to `main`, the
weekly run and manual runs reuse no check: they run every one, and record
each pass. Records are artifacts of those runs, found through the API;
nothing is taken from the Actions cache, and nothing a pull request's run
uploads is ever read by another run. Built toolchains are taken from runs
on `main` the same way, by every run, and checked against their build
records.

A check whose component is not in the tree is NOT APPLICABLE, and the
safety check is NOT RUN while the tree has Jasmin code but no safety
component. Both follow from the tree, are decided on every run, and are
listed as such in the summary of `all-checks`: a green `all-checks` does not
mean those checks ran.

A recipe names its inputs only through the paths of the tree it builds;
`source.py` rejects a recipe that includes another file than
`mk/common.mk` or names another check's recipe or rules, but it cannot see
a path a recipe assembles from variables, so recipes name files literally.

The weekly run also builds the toolchain from scratch on every platform
and compares it with the stored build.

## Scripting

Shell is glue only: it installs packages, sets up the environment and runs
steps in order. Anything that parses text, computes a key or a digest,
generates a file or decides whether a check passed is written in Python,
with the standard library only, run with `python3 -I`, with tests in
`tests/`. The workflows run one pinned Python on every runner
(`.github/actions/python`). The build of the toolchain itself,
`toolchain/build.sh`, drives upstream build systems and stays shell.
