# R02 typed structured-report log format — 2026-09-19

Task ID / parent milestone: `R02`, with the R04 acceptance producer and
post-run verifier integration.

Exact capability kind:id scope: existing `report:client-boundary` service
workload evidence only. No capability status or release result was promoted.

Starting state:

- canonical checkout: `ClamAV-32gb`
- branch: `largefile-roadmap-qualification`
- starting HEAD: `98eaef89`
- no remote action, workflow action, dependency installation, or usage reset

Change:

`kind=report` workload rows now use an explicitly typed structured-report log
validator. The independently validated JSON report remains authoritative for
the exact alert and native-width offset, while the supplementary console log
must only prove the outcome shape (`target: FOUND`, `target: OK`, or
`target: INCOMPLETE ...`). Bare `FOUND` is accepted only on this typed path;
CLI/service/legacy rows still require their exact signature semantics and
offset checks. Wrong structured alerts, contradictory verdicts, and unrelated
FOUND text remain rejected.

Follow-up refinement: clean typed reports now also require a real `target: OK`
summary line, and incomplete typed reports require `target: INCOMPLETE ...`;
arbitrary text without `FOUND` cannot satisfy the outcome contract.

Validation:

- `PYTHONPATH=tools python3 -B -m unittest discover -s tools -p '*_test.py'` — 202 passed, 2 expected macOS filesystem skips.
- `sh tools/largefile_service_evidence_check_test.sh` — passed.
- `sh tools/largefile_source_guards.sh` — passed; 604 capability entries.
- `python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — passed.
- `git diff --check` — passed.

Remaining boundary:

Fresh current-source certified Linux client/daemon outputs, full-size
materialized fixtures, resource/fanotify evidence, and final release
qualification remain required. This is development verifier evidence only.

Follow-up parity correction (2026-09-19): the direct
`largefile_clamd_report_protocol.py` verifier now independently requires the
structured report's `max_scan_size` to equal the certified 64-GiB logical
budget and rejects `logical_bytes` above that budget. Its FILDESREPORT wire
fixture now includes the required budget field, and a focused regression
covers both wrong-budget and over-budget reports. This closes an independent-
verifier gap; it does not promote any capability.
