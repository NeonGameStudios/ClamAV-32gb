# R04 runtime POC duplicate-row hardening — 2026-09-13

Task ID / parent milestone: `R04` / `R05`.

Observed gap: `load_poc_results()` converted `poc/results.tsv` directly to a
dictionary. Duplicate file keys were therefore silently overwritten, allowing
the last row to replace an earlier independently captured POC result.

Change: the producer now rejects duplicate file rows before creating the
lookup map. Added `test_duplicate_poc_file_rows_are_rejected`, which mutates a
valid fixture with a duplicate `32g-edge.bin` row and verifies a fail-closed
`ValueError`.

Verification:

- `PYTHONPATH=tools python3 -B -m unittest -v tools.largefile_runtime_acceptance_case_producer_test` — passed, including the new regression.
- `git diff --check` — passed.
- `python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — passed.

No qualification status changed. No usage reset, installation, commit, push,
workflow action, or remote mutation was performed.

State: `implemented; development-verified`.
