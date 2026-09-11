# Task receipt: R10 structured-report version binding

Task ID / parent milestone: `R10` / `R00`

Scope: tighten the structured clamd report consumer so numeric verdicts are
accepted only from the supported report version. The existing versionless
string-valued incomplete fallback remains compatible by design. This is a
bounded protocol slice; it does not claim ingress or release qualification.

Canonical checkout and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

Source manifest SHA-256 captured after the follow-on source/test corrections
and before this receipt was updated:
`952ee0e289bbc991ff53505db0213f9f3e9201e7ccb09f8a4e9a5768a7ed7091`.

## Correction

`common/clamdcom.c::scan_report_json_status()` now requires a numeric
`verdict` report to contain integer `version: 1` before interpreting its
completion, status, or detection result. Reports with a missing or unsupported
numeric version fail closed. The versionless string-valued incomplete fallback
used by the compatibility tests is unchanged.

`unit_tests/check_clamd.c` adds a regression for missing and unsupported
numeric report versions, and the source guard pins the version check.

## Verification

- `PYTHONPATH=tools python3 -B -m unittest largefile_acceptance_cases_test largefile_status_snapshot_test` — **25 passed**.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `diff -u docs/largefile-inventory.tsv <(sh tools/largefile_inventory.sh)` — **passed**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- `git diff --check` — **passed**.
- A current C relink was not available: the retained CMake binary predates
  this edit, and the available container lacks JSON-C development headers.
  No software was installed.

Release readiness remains intentionally blocked and unchanged at 597 total,
0 qualified, 143 bounded, 440 pending, 14 allowlisted unsupported,
0 unsupported required, and 583 blockers. No certified Linux x86-64,
full-size, sanitizer, privileged, production-service, or R04 acceptance
evidence was produced. No remote execution, MCP-SSH, usage reset, GitHub
workflow action, commit, or push was used.

State: protocol implementation and source/host controls verified; current
linked C runtime evidence and release qualification remain open.

## Follow-on source/test correction

The new C regression's JSON literals were corrected to use valid C string
escaping. The R10 version check remains source-verified because the retained
ARM64 CMake binary predates the edit and the available container lacks the
JSON-C development headers required for a current relink.
