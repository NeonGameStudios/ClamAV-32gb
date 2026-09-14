# Task receipt: R04 development acceptance capture revalidation

Task ID / parent milestone: `R04` / `R00`

Scope: produce and validate small current-source acceptance records for the
clamscan file and stdin clean, detection, and limit boundaries. These records
are development evidence only and cannot qualify the 32-GiB or certified-
platform cases.

Prerequisites verified:

- Canonical source: `<repository-root>`.
- Branch: `largefile-roadmap-qualification`.
- Rebuilt scanner: `/private/tmp/clamav-largefile-static-build/clamscan/clamscan`.
- The repository test CVD certificate directory was supplied explicitly;
  omitting it correctly caused the scanner to reject its missing default
  `/usr/local/etc/certs` directory.

Capture and validation:

- `largefile_development_acceptance_capture.py` completed with exit 0 and
  wrote 6 records under `/private/tmp/clamav-r04-capture-20260907h`.
- File and stdin detection reports both bind
  `LargeFile.R04.Runtime.Detection.UNOFFICIAL` at offset 25, with
  `DETECTION_TERMINATED` and a 54-byte root.
- File and stdin clean reports both bind `COMPLETE`, status 0, no alert, and
  complete logical traversal of the 54-byte fixture.
- File and stdin limit reports both bind
  `Heuristics.Limits.Exceeded.MaxFileSize`, status 24 in the structured report,
  no alert, and zero logical/parser/matcher work. The file limit has no
  staging; the unknown-length stdin limit has only the exact 9-byte
  (`MaxFileSize + 1`) staging sentinel.
- The CLI process statuses are exactly `0, 1, 2` for clean, detection, and
  limit in both modes. The stdin limit previously leaked library status 24;
  `clamscan/manager.c` now preserves detection precedence and normalizes
  non-detection admission failures to CLI status 2.
- All six records bind the same source-manifest, build, configuration,
  fixture, oracle, and database identities.
- Source manifest SHA-256:
  `b0d336f47f0990ee145076afb1c6428dcafc59626d320153a35acdd0736bcc78`.
- Build identity SHA-256:
  `312e31893c2083a64d6ec305657d7798f82c7510ce29c7fad4e7ecb9a9b24443`.
- CMakeCache SHA-256:
  `e2a9a9c78ab10e1058614aec90269f6c4e4a0c890f30b07edc4834ad5d918fd7`.
- Acceptance record file SHA-256:
  `9612d28a89a7ca2629e8c11e0a54e2ffe0c352e3d64b556b619e5c47a899173c`.

Full-size/certified evidence produced, or explicitly not run: no 32-GiB
materialized edge, Linux x86-64 Release/sanitizer run, production CVD,
daemon/service record, or on-access evidence was produced.

Commands and exits:

- `python3 -B tools/largefile_development_acceptance_capture_test.py` — 0,
  1 test passed.
- `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py` — 0,
  3 tests passed, including the bounded stdin staging rule.
- `python3 -B tools/largefile_status_snapshot_test.py` — 0, 12 tests passed.
- Disposable ARM64 `cmake --build ... --target clamscan -j2` — 0.
- Disposable ARM64 CTest `clamscan` — passed.
- Disposable ARM64 CTest `largefile_clamscan_admission` — passed; the real
  file and stdin MaxFileSize regressions both return CLI status 2.
- `sh tools/largefile_source_guards.sh` — 0; 597 capabilities and all
  source/readiness/acceptance guards passed.
- `git diff --check` — 0.

Follow-on current-source revalidation:

- A fresh disposable ARM64 run of
  `tools/largefile_development_acceptance_capture.py` completed with exit 0
  and wrote 6 records under
  `/private/tmp/clamav-r04-development.jsjwxT`.
- The run supplied the repository's existing
  `unit_tests/input/signing/verify` directory. The intentionally omitted
  certificate-directory control failed closed before the successful rerun;
  no database or report was accepted from that control.
- `python3 -B tools/largefile_acceptance_cases.py --manifest
  docs/largefile-capabilities.tsv --map
  docs/largefile-capability-case-map.tsv --records
  /private/tmp/clamav-r04-development.jsjwxT/provenance/acceptance-cases.tsv
  --check-records --evidence-root
  /private/tmp/clamav-r04-development.jsjwxT` — 0; 6 records passed
  capability-map and artifact binding validation.
- The current capture binds source-manifest SHA-256
  `0b186975cd257a4f29d7939c839eb099bdad12e7aee3ae00b7f583f9297d6239`,
  build-identity SHA-256
  `5c00f0036650dbc9b7540f72de2663a7b206dc8c1a41b374e8a13c6fbd7316b2`,
  CMakeCache SHA-256
  `e2a9a9c78ab10e1058614aec90269f6c4e4a0c890f30b07edc4834ad5d918fd7`,
  and acceptance-record SHA-256
  `aa6c0feeba1d76e8a453f53b9f086ec8823999ecb2d6b45ce974307d9be53341`.
- The reports again prove clean completion, exact detection at offset 25,
  and MaxFileSize incomplete results for both file and stdin. This remains
  ARM64 development evidence, not a certified or 32-GiB qualification record.

Remaining failures / next slice: feed retained records through the authorized
runner's R04 verifier after the current source is rebuilt there; extend the
same binding to library, daemon, milter, and full-size service producers.

State: `development-verified`; release readiness remains blocked.
