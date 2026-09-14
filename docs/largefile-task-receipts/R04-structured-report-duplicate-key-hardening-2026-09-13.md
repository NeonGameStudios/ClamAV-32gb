# R04 structured-report duplicate-key hardening — 2026-09-13

Task ID / parent milestone: `R04` / `R10`.

Observed gap: report readers used Python's default JSON decoder, which accepts
duplicate object keys and keeps only the last value. A malformed or tampered
report could therefore replace a status, completion, alert signature, or
offset before the acceptance checks examined it.

Change: added a shared strict JSON-object loader in
`tools/largefile_acceptance_cases.py` and wired it into the runtime producer,
service workload verifier, service input identity verifier, development
service/capture readers, and direct clamd report protocol. Duplicate keys and
non-object JSON now fail closed.

Verification:

- `PYTHONPATH=tools python3 -B -m unittest -v tools.largefile_acceptance_cases_test tools.largefile_acceptance_resources_test tools.largefile_runtime_acceptance_case_producer_test tools.largefile_development_service_capture_test tools.largefile_service_workload_check_test` — passed.
- `git diff --check` — passed.
- `python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — passed.

No qualification status changed. No usage reset, installation, commit, push,
workflow action, or remote mutation was performed.

State: `implemented; development-verified`.
