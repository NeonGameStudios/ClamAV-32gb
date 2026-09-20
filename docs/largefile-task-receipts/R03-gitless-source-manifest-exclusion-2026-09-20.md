# R03 Git-less source-manifest exclusion — 2026-09-20

## Scope

Make the source identity fallback safe and practical for a source delivery
without `.git`. Retained `pcre-scale-development-*` fixture payloads are
development evidence, not candidate source, and must not be hashed into the
immutable source manifest.

## Change

`tools/largefile_source_manifest.sh` now excludes root-level retained
`pcre-scale-development-*`, `provenance/`, `evidence/`, and
`largefile-evidence-*` payloads in both its Git and Git-less paths while
continuing to include source files, build controls, fixtures, verifiers, and
the manifest helper itself. Regression tests cover a dirty Git checkout and a
Git-less delivery with retained fixture/evidence payloads, build output,
transport archive, and `libnull.a`. They confirm only the source file and
helper remain in the minimal Git-less manifest and that retained evidence does
not change the Git-mode manifest.

Parent commit: `12cb52f130e873c0e8989280b0f0d58a3f070eec`.

## Verification

- `python3 -B tools/largefile_status_snapshot_test.py` — 14/14 passed.
- `sh tools/largefile_source_guards.sh` — passed for all 604 capability rows
  and source/readiness guards.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — 229 passed,
  2 expected skips.
- `git diff --check` — passed.

No source capability was promoted. No full-size, certified Linux x86-64,
sanitizer, production-CVD, fanotify, or release evidence was produced. No
software was installed or downloaded, and no remote mutation was performed.

State: `development-tooling-verified; current-source-staging-still-blocked`.
