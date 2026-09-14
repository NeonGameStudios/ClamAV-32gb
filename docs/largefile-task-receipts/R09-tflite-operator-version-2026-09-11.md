# R09 TFLite OperatorCode version validation — 2026-09-11

## Scope

Close a concrete correctness gap in the bounded TFLite FlatBuffer semantic
walk: `OperatorCode.version` is a signed FlatBuffers `int32`, so negative
encoded values must not be admitted as valid model metadata.

## Changes

- `libclamav/scanners.c` now rejects absent-zero and out-of-range signed
  `OperatorCode.version` values before semantic validation can succeed.
- `unit_tests/check_clamav.c` adds a regression that mutates the fixture's
  version field to `UINT32_MAX` and requires `CL_EPARSE`, a cleared verdict,
  and non-cacheability.
- `tools/largefile_source_guards.sh` now guards the version-validation path.

## Verification

- isolated current-source C parser harness — **7/7 passed**, including the
  valid control, five existing malformed tensor/operator cases, and the new
  negative-version mutation;
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed;
  2 expected skips**;
- `sh tools/largefile_source_guards.sh` — **passed**, including the 597-row
  capability manifest and acceptance controls;
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — **passed**;
- regenerated `docs/largefile-inventory.tsv` matches the inventory generator;
- `git diff --check` — **passed**;
- current source-manifest SHA-256:
  `42c96cebd6a3fa26eac45037b62bb1b65380c92dd9eccae6f15912ed691ce7e2`.

## Boundary

The linked C test/build remains unavailable in this environment because the
retained ARM64 Docker image lacks JSON-C development headers (`json.h`) and a
coherent JSON-C/Zlib/check toolchain. No software was installed, no
remote SSH/remote execution was used, no usage-reset or banked-reset credit was
used, and no GitHub workflow action was triggered.

No capability was promoted. Certified Linux x86-64 Release, sanitizer,
full-size, production-service, R04 acceptance, and complete TFLite semantic
qualification remain open; release readiness remains blocked.
