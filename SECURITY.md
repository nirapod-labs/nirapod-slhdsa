# Security policy

## Status

This project is under development and has not been released. No version is
supported for production use yet. Reports are still welcome and will be
handled as below.

## Scope

In scope:

- the Jasmin implementation of SLH-DSA and its hash primitives
- the C API and wrapper in `include/` and `capi/`
- the assembly the build generates from the Jasmin sources
- the toolchain patch series under `toolchain/`, where a defect could change
  generated code or weaken an analysis result
- proofs and analysis results whose stated scope is wrong

Timing side channels observable from software, including cache and
speculative-execution channels, are in scope. Fault injection and physical
side channels are covered only to the extent stated in
[`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md).

## Reporting a vulnerability

Please report privately through GitHub's private vulnerability reporting:
open the repository's **Security** tab and choose **Report a vulnerability**.
Do not open a public issue for a suspected vulnerability.

Include the affected revision, architecture and parameter set, and a
reproducer if you have one. We will acknowledge the report, agree on a
disclosure timeline with you, and credit you unless you prefer otherwise.
