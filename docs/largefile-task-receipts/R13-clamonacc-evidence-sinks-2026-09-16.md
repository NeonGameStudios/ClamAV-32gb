# Task receipt: R13 clamonacc evidence sinks — 2026-09-16

## Scope

Implement the application-side retention needed to move from the independent
fanotify capture primitive to real clamonacc evidence. This slice does not run
the six-case qualification.

## Changes

- `clamonacc --report-json=FILE` now retains one validated, terminating clamd
  structured report object per on-access request and emits one fail-closed
  fallback report after client-side admission or transport failures, including
  after all configured retries fail.
- The report is published only after the protocol terminator is received, so a
  truncated or duplicate frame sequence cannot be mistaken for a retained
  report. The JSON report carries the same process-local
  `clamonacc_event_id` assigned before the permission scan begins, making the
  report-to-permission join explicit instead of relying on stream order.
- The fanotify evidence verifier now requires each prevention scan-report
  artifact to carry the same `clamonacc_event_id` as its selected permission
  event; monitoring-only reports must carry zero because they have no
  permission-event join.
- `tools/largefile_fanotify_case_binder.py` now joins the observer's selected
  event to the real clamonacc permission JSONL, actor result and raw scan
  report using path/PID/metadata plus the explicit ClamAV event ID. It emits
  verifier-shaped artifacts only after rejecting ambiguous matches, failed
  response writes, mismatched IDs and already-bound report identities.
- `clamonacc --fanotify-evidence=FILE` now emits JSONL after each permission
  response with the real `permission_response`, response-write result, event
  metadata, path, process-local event sequence and scan status.
- Evidence writes are serialized across worker threads and flushed before the
  event descriptor is closed. The output is intentionally not presented as a
  complete R13 proof: the runner must bind it to the raw observer event,
  fixture digest, case envelope and process exit.

## Checks

- `python3 -B tools/largefile_fanotify_capture_test.py` — 7/7 passed.
- `python3 -B tools/largefile_fanotify_evidence_test.py` — 18/18 passed after
  adding the report-to-permission event-ID binding regression.
- `python3 -B tools/largefile_fanotify_case_binder_test.py` — 5/5 passed.
- `python3 -B tools/largefile_acceptance_cases_test.py` — 15/15 passed.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — 604
  capabilities passed.
- `sh tools/largefile_source_guards.sh` — passed, including the 604-entry
  capability manifest and release-blocked readiness checks.
- `git diff --check` — passed.
- Disposable ARM64 Clang/CMake build with JSON-C, OpenSSL, CURL and zlib
  development packages installed only inside the throwaway container:
  `cmake --build /tmp/clamav-evidence-build --target clamonacc -j2` linked
  successfully at 100%.
- Host C syntax checking remains unavailable because the checkout host lacks
  OpenSSL development headers; no host software was installed.

## Boundary

The real Linux fanotify cases remain externally blocked by the Sonic1
workspace's current free-space and source-synchronization state. No
qualification status is promoted by this slice.

State: `implementation-added; qualification-still-open`
