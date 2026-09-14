# R09 Python marshal string-reference table correction — 2026-09-11

## Scope

Correct the required `CL_TYPE_PYTHON_COMPILED` parser's legacy marshal
`TYPE_STRINGREF` boundary. Python 2 marshal uses `R` to index the separate
interned-string table populated by `t`; it is not an alias for Python 3's
`FLAG_REF` object table.

## Changes

- `libclamav/scanners.c` now tracks bounded legacy interned-string entries
  separately from flagged marshal objects.
- `TYPE_STRINGREF` indexes only the interned-string table and remains
  fail-closed for forward/out-of-range references.
- The prior synthetic flagged-`s` fixture is replaced with a legal `t`/`R`
  legacy fixture.
- Added a malformed control proving that `R 0` without a prior `t` entry is
  rejected.
- Added a malformed control proving that `R|FLAG_REF` is rejected rather than
  treated as both a lookup and a new reference-table entry.

## Verification

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — exit 0,
  147 tests passed with 2 expected skips;
- `sh tools/largefile_source_guards.sh` — exit 0; the 597-row capability
  manifest, acceptance map, snapshot, schema, producer, service, protocol,
  boundary, and source checks passed;
- `sh -n tools/largefile_source_guards.sh` — exit 0;
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — exit 0;
- `git diff --check` — exit 0;
- audited source-manifest SHA-256:
  `41f94617e2b89d0cca666ba26f3d703349a03e80df609a142e31960e362464ee`;
- host-side linked C execution remains unavailable because the retained
  build/image lacks a coherent JSON-C, Check, and OpenSSL development
  toolchain;
- no package installation, remote source export, usage-reset/banked-reset
  action, or GitHub workflow action was performed.

## Boundary

The implementation is development-level until linked current-source C tests,
independent format-8 evidence, certified Linux x86-64 Release/sanitizer
evidence, full-size materialized cases, production-service evidence, and R04
acceptance records are available. Release readiness remains blocked.

State: development-verified
