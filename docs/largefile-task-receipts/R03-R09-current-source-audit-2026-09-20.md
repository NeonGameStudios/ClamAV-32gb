# Task receipt: current-source and R09 audit — 2026-09-20

Task ID / parent milestone: `R03` / `R09`

## Scope

This receipt records the follow-up after the current-source staging boundary was
reached. It does not promote any capability or claim release qualification.

## Candidate identity

- Worktree: `largefile-roadmap-qualification`
- Candidate commit: `53d4d777`
- Worktree state after verification: clean
- Capability manifest: 604 rows
- Readiness snapshot: 0 qualified, 147 bounded, 443 pending, 14 allowlisted unsupported; release readiness remains blocked

## R09 source audit

The seven required R09 rows are implemented in the current source with
fail-visible behavior and registered regressions:

- fuzzy-image admission and bounded reader-backed matching
- `CL_TYPE_AI_MODEL` structural GGUF, ONNX, and TFLite admission
- `CL_TYPE_IGNORED` incomplete/non-cacheable policy while retaining outer raw matching
- `CL_TYPE_PYTHON_COMPILED` bounded, non-executing marshal walking
- RAR/RAR-SFX backend-unavailable and enabled-backend status boundaries

The manifest keeps these rows `pending` because production-linked execution,
sanitizer evidence, certified Linux x86-64 execution, production database/service
coverage, materialized-large-file coverage, Sonic1 current-source execution, and
final qualification remain required. No source-level evidence justified changing
that classification during this audit.

## Local verification

The following completed successfully against the candidate checkout:

```text
sh tools/largefile_source_guards.sh
python3 -B -m unittest discover -s tools -p 'largefile*test.py'
  Ran 229 tests in 9.549s
  OK (skipped=2)
python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md
git diff --check
```

The two skipped tests are the repository's expected skips. No software was
installed and no required feature was disabled.

## External qualification boundary

Read-only MCP-SSH access with host `sonic1` and login profile
`sonic1-camera-key` succeeds. The existing Docker container provenance is:

- container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`
- image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- `/src` bind: `/tmp/clamav-32gb-current-20260915`
- state: running

That mount is the stale dirty source tree, not candidate `53d4d777`. The durable
transfer ledger still records the interrupted current-source handoff
`transfer_6a4e4e...` and the later candidate archive was denied with
`file_write_limit_exceeded` before remote write. The denied large archive was not
retried, no alternate destination was used, and no manual chunking or untracked
remote process was started.

The retained exact-source directory `/tmp/clamav-32gb-7f3458c4` still exists
on Sonic1 and has a Git checkout at baseline `aa6c0077`, matching the earlier
Release CTest receipt. A read-only `git cat-file -e 7633c81d^{commit}` check
failed, so that repository does not already contain the current candidate. A
bounded 2,131,060-byte source-only patch from `aa6c0077` to `7633c81d` was then
submitted through the documented client-local durable handoff with SHA-256
`4d352c2c39300f686cf1bb55b3990eca571e0a63954e39eabfbe61c202f64b07`; MCP-SSH
denied it before remote write with `file_write_limit_exceeded`. No retry with a
different destination or manual chunking was attempted.

## Result

The current source passes all available local guards and tooling tests, but the
roadmap's remaining R03/R09 qualification evidence cannot be honestly produced
until a current-source handoff or an administrator-configured validation path is
available on Sonic1. This receipt preserves that boundary without changing
capability status.
