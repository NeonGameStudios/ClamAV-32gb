# R04 resource-binding duplicate-row hardening — 2026-09-13

Task ID / parent milestone: `R04` / `R13`.

Observed gap: the standalone resource sidecar binder built its acceptance-case
lookup with a dictionary comprehension. A duplicated acceptance-case row was
therefore not rejected at the binding boundary, even though the normal full
record validator rejects duplicates.

Change: `acceptance_resources.bind()` now checks every acceptance-case key for
uniqueness before validating or mutating the record file. Added
`test_bind_rejects_duplicate_acceptance_case_rows`.

Verification:

- `PYTHONPATH=tools python3 -B -m unittest -v tools.largefile_acceptance_resources_test` — passed, including the new regression.
- `git diff --check` — passed.
- `python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — passed.

No qualification status changed. No usage reset, installation, commit, push,
workflow action, or remote mutation was performed.

State: `implemented; development-verified`.
