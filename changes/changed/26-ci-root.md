- The CI tooling moved from `tools/ci/` to `ci/`, and `tools/changes.sh` to
  `ci/changes.sh`: a check now runs with
  `python3 ci/check.py run <check> <platform>`.
