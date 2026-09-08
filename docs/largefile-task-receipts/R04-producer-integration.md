# Task receipt: R04 service/runtime acceptance producer integration

Task ID / parent milestone: `R04` / `R00`

Scope: bind the existing service workload evidence to the reviewed capability
case map without relabeling unrelated workloads or claiming qualification.

Changes made:

- Added `tools/largefile_acceptance_case_producer.py` with an explicit,
  fail-closed workload-label table for the direct `clamscan`, `clamd`, and
  `clamdscan` service cases.
- Added `tools/largefile_runtime_acceptance_case_producer.py`; runtime POC
  reports now use `--report-json`, and the runtime producer binds direct file
  and stdin detection-edge cases to the POC results and process/oracle rows.
  It also binds exact-size file/stdin clean-edge reports to a valid benign
  database, requiring `COMPLETE`, status 0, no alert, full logical-byte
  traversal, and no skipped operations.
  The runtime gate also runs explicit `AlertExceedsMax=no` file/stdin probes;
  their exact `LIMIT_INCOMPLETE` reports, status 2, reason, counters, logs,
  and artifacts are bound to the two `limit-edge` records. The alert-enabled
  policy probes remain separate controls.
- Added `tools/largefile_development_acceptance_capture.py`, a small-fixture
  current-source capture path that emits two retained R04 records (clamscan
  file and stdin detection) outside the source tree. It binds the source
  manifest, build cache, structured report, exact debug offset, POC row,
  database, and process status before writing `acceptance-cases.tsv`.
- Detection report validation accepts `status=0` for daemon-style reports and
  `status=1` (`CL_VIRUS`) for current clamscan reports while retaining strict
  clean/limit status rules. This was confirmed by the current ARM64 build,
  which emitted status 1 with the expected signature and offset 25.
- Derived case suffixes from the validated structured report completion state:
  clean, detection-terminated, or limit-incomplete.
- Copied source/build/config/oracle/database identities and retained log/report
  paths into each record; fixture identity comes from
  `service-inputs-before.json`.
- Invoked the producer from `largefile_service_qualification.sh` before the
  final `SHA256SUMS` is written, so acceptance records are part of the sealed
  service evidence set.
- Made the service verifier and authoritative release gate recompute recorded
  artifact hashes and fixture identity. A tamper regression proves a modified
  retained source manifest is rejected.

Verified commands and results:

- `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py` — exit
  0, binding two detection, two clean, and two limit records in the synthetic
  fail-closed producer fixture.
- `python3 -B tools/largefile_development_acceptance_capture_test.py` — exit
  0, binding two records and all retained artifact hashes with a runner stub.
- `python3 -B tools/largefile_clamd_report_protocol_test.py` — exit 0, proving
  the FILDESREPORT command carries the descriptor and a framed JSON report
  with the exact detection offset.
- Disposable existing ARM64 Docker build capture — exit 0, wrote two real
  current-source records under `/private/tmp/clamav-r04-rebuilt-evidence.qhZYRi`;
  both reports returned `DETECTION_TERMINATED`, status 1, and offset 25.
- `sh tools/largefile_service_evidence_check_test.sh` — exit 0, including the
  integrated acceptance-record verifier.
- `sh tools/largefile_runtime_evidence_check_test.sh` — exit 0, including the
  integrated acceptance-record verifier.
- `sh tools/largefile_source_guards.sh` — exit 0; 597 manifest entries and all
  producer regressions passed.

Explicit non-claims: the development capture is ARM64 and uses a small
fixture, so it is not certified Linux x86-64, 32-GiB, sanitizer, daemon,
library, parser, matcher, feature, fanotify, or release evidence. The service producer
covers only the explicit workloads listed in its mapping; the runtime producer
now has fail-closed clean/limit bindings, but those cases remain unqualified
until the certified runner produces and seals the live evidence.

State: `development-verified`
