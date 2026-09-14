# R09 Python marshal `TYPE_STRINGREF` support — 2026-09-11

## Scope

Close a valid-input gap in the required `CL_TYPE_PYTHON_COMPILED` parser.
Modern marshal streams can encode a string as `TYPE_STRINGREF` (`R`) and
refer to an earlier flagged object; the bounded walker previously rejected
that legal token as an unknown object type.

## Changes

- `libclamav/scanners.c` now consumes the four-byte `TYPE_STRINGREF` index and
  requires it to refer to an already-accounted bounded marshal reference.
- `unit_tests/check_clamav.c` adds and registers a valid legacy-layout fixture
  containing a flagged string followed by `TYPE_STRINGREF`.
- `docs/largefile-capabilities.tsv` records the bounded string-reference
  coverage for `CL_TYPE_PYTHON_COMPILED`.
- `tools/largefile_source_guards.sh` guards both the implementation and test.

## Verification

- `sh tools/largefile_source_guards.sh` — **passed**, including the 597-row
  capability manifest and acceptance controls;
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed;
  2 expected skips**;
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — **passed**;
- regenerated `docs/largefile-inventory.tsv` matches the inventory generator;
- `git diff --check` — **passed**;
- current source-manifest SHA-256:
  `d9d27ba8c7e7607471021007892f78a07914db276c80d6e586c4ea086361ee21`.

## Boundary

The linked current-source C test remains unavailable because the retained
ARM64 Docker image lacks JSON-C development headers (`json.h`) and a coherent
JSON-C/Zlib/check toolchain. The new C regression is source-registered and
guarded but not claimed as linked execution. No software was installed, no
remote SSH/remote execution was used, no usage-reset or banked-reset credit was
used, and no GitHub workflow action was triggered.

No capability was promoted. Independent format-8, certified Linux x86-64
Release, sanitizer, full-size, production-service, R04 acceptance, and final
release qualification remain open; release readiness remains blocked.
