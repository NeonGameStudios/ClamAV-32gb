# Task receipt: independent service resource evidence

Task ID / parent milestone: `R02` / five-issue follow-up (`R04`, `R10`)

Date: 2026-09-11 UTC

## Finding

The service qualification producer enforced RSS and temporary-space limits
while running, but the post-run service evidence checker only required pass
markers and declared budgets. A tampered retained peak could therefore remain
undetected if the outer `SHA256SUMS` file was regenerated.

## Change

- `tools/largefile_service_qualification.sh` now retains RSS/temp sample counts
  alongside the measured service RSS peak, milter RSS peak, parallel-client
  RSS peaks, and temporary-space peak already used by the producer.
- `tools/largefile_service_evidence_check.sh` now requires the temporary-space
  pass marker, positive sample counts, canonical numeric peak fields, the
  fixed 64-GiB temporary budget, and measured peaks within the overall
  32-GiB RSS / 64-GiB temporary budgets. It also rechecks the retained
  parallel-client and milter elapsed times against the retained latency budget.
- `tools/largefile_service_evidence_check_test.sh` adds checksum-refreshed
  tamper regressions for an RSS peak and a temporary-space peak above their
  budgets.

## Verification

- `sh tools/largefile_service_evidence_check_test.sh`: passed; focused service,
  workload, and oversized-probe suites passed 28 + 10 + 22 checks with 2
  expected Linux filesystem skips.
- `python3 -B -m unittest discover -s tools -p '*_test.py'`: 147 passed, 2
  expected Linux filesystem skips.
- `sh tools/largefile_source_guards.sh`: passed all 597 capability and source/
  evidence controls.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`:
  passed.
- `git diff --check` and shell syntax checks: passed.
- Current source manifest: SHA-256
  `ae8307730da2dedcf28359186164eaedf199de9cc45853e9ec168548b40c90f3`, 1,678
  entries.

No capability status was promoted. This is development verification only;
certified Linux x86-64, sanitizer, full-size/materialized, production-CVD,
privileged on-access, and final R04 qualification evidence remain required.
No remote runner, MCP-SSH, software installation, usage reset, GitHub
workflow trigger, commit, or push was used.
