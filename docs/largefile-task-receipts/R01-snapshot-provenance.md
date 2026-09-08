# Task receipt: R01 snapshot/evidence provenance

Task ID / parent milestone: `R01` / `R00`

Exact capability kind:id list: release-readiness provenance tooling; no runtime
capability row promoted

Starting commit and working-tree/source manifest identity: starting commit
`ff8905891b2b58a66c71859ab2c807cc4dee2dec`; worktree was already dirty with the
roadmap/status/tooling changes recorded in `docs/largefile-task-ledger.md`.

Prerequisites verified: canonical checkout and branch confirmed; roadmap, PLAN,
current snapshot, and AGENTS instructions read; 597-row capability manifest
validated; certified Linux x86-64 runner and CMake build were not available on
this macOS host.

Owned files and excluded shared files: owned `tools/largefile_status_snapshot.py`,
`tools/largefile_status_snapshot_test.py`, `tools/largefile_source_manifest.sh`,
`32gb-current-snapshot.md`, and this receipt. No application parser or shared
runtime implementation files were changed.

Observed failing case and expected behavior: a tracked generated snapshot that
embedded `HEAD` became stale after the normal commit containing the snapshot.
Promotion metadata could also enter the source-manifest identity through the
tracked dashboard. Expected behavior is deterministic tracked status text,
external source revision provenance, and source identity unaffected by generated
dashboard/task-ledger edits.

Changes made: removed Git `HEAD` from tracked snapshot content; added optional
JSON `--provenance-output` containing source revision, input hashes, snapshot
hash, and readiness result; made the Git source manifest include candidate
untracked files while excluding only generated dashboard/task-ledger paths and
the manifest output itself; added isolated Git commit/freshness, source-manifest
fixed-point, and untracked-source regressions; refreshed the tracked snapshot.

Commands, exits, logs and fixture/database hashes:

- `python3 -B tools/largefile_status_snapshot_test.py` — exit 0, 12 tests passed.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — exit 0.
- `sh tools/largefile_source_guards.sh` — exit 0 after the final verification.
- `sh tools/largefile_service_evidence_check_test.sh` — exit 0.
- `git diff --check` — exit 0.
- `sh tools/largefile_release_readiness.sh --status` — exit 1 with
  `release_readiness=blocked`, as expected; no qualification claim made.

Development tests passed: snapshot unit/regression suite and source/readiness
guards passed. No full-size runtime, sanitizer, service, or certified-runner
evidence was produced.

Full-size/certified evidence produced, or explicitly not run: not run; the
required Linux x86-64 runner/CMake toolchain is unavailable on this host.

Remaining failures / next slice: R02 report/resource contract reconciliation,
R03 certified runner/build, and R04 capability-specific acceptance records remain
open. The release gate remains blocked with 583 rows.

State: `development-verified`
