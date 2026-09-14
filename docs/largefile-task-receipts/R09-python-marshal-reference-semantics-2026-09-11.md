# R09 Python marshal reference-registration semantics — 2026-09-11

## Scope

Close a malformed-input gap in the required `CL_TYPE_PYTHON_COMPILED`
non-executing marshal walker. A Python 3 `FLAG_REF` bit only registers types
that CPython inserts into its reference list; singleton values such as
`None` are decoded but are not reference-table entries.

## Changes

- `libclamav/scanners.c` now registers flagged objects only for the marshal
  types that support CPython reference registration, while retaining the
  separate legacy `TYPE_INTERNED` table used by `R`.
- Added a regression proving that `FLAG_REF` on `None` does not create a
  later-valid `TYPE_REF` target.

## Verification

- Focused host suite: `python3 -B -m unittest discover -s tools -p '*_test.py'`
  — exit 0, 147 tests passed with 2 expected skips;
- `sh tools/largefile_source_guards.sh` — exit 0; the 597-row capability
  manifest, acceptance map, snapshot, schema, producer, service, protocol,
  boundary, and source checks passed;
- `sh -n tools/largefile_source_guards.sh` and `git diff --check` — exit 0;
- audited source-manifest SHA-256:
  `cdd019df2292fe2212319f8c45de3376b5b6b0b43e3797eb40a68b866dd77ba7`;
- no package installation, remote source export, usage-reset/banked-reset
  action, or GitHub workflow action was performed.

## Boundary

Linked current-source C execution remains unavailable because the retained
build/image lacks a coherent JSON-C, Check, and OpenSSL development
toolchain. Certified Linux x86-64 Release/sanitizer, independent format-8,
full-size, production-service, R04 acceptance, and final release
qualification remain open. Release readiness remains blocked.

State: development-verified
