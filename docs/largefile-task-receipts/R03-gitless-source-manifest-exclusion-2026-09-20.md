# R03 Git-less source-manifest exclusion — 2026-09-20

## Scope

Make the source identity fallback safe and practical for a source delivery
without `.git`. Retained `pcre-scale-development-*` fixture payloads are
development evidence, not candidate source, and must not be hashed into the
immutable source manifest.

## Change

`tools/largefile_source_manifest.sh` now excludes root-level
`pcre-scale-development-*` payload directories in its Git-less path while
continuing to include source files, build controls, fixtures, verifiers, and
the manifest helper itself. A regression test covers a Git-less delivery with
the retained 8-GiB fixture, build output, transport archive, and `libnull.a`.
The test confirms only the source file and helper remain in the manifest.

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
