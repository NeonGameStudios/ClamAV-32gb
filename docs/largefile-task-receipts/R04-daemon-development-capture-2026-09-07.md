# Task receipt: R04 direct daemon development capture

Task ID / parent milestone: `R04` / `R00`

Scope: retain current-source ARM64 development records for the six direct
structured clamd report protocols. This is not certified service or release
qualification.

The capture ran from `/Volumes/512gbNVME/github-external/ClamAV-32gb` using
the rebuilt `/private/tmp/clamav-largefile-static-build/clamd/clamd` inside a
disposable `clamav-largefile-local-toolchain2:latest` container. The container
installed only its missing `libjson-c5` runtime; no host or repository software
was installed. The daemon socket and temporary directory were on native
container storage because the host-mounted filesystem cannot apply clamd's
Unix-socket permissions.

The retained evidence directory is:

`/private/tmp/clamav-r04-service-capture-20260907-final2`

It contains 18 records: six each for `COMPLETE`,
`DETECTION_TERMINATED`, and `LIMIT_INCOMPLETE` across:

- `SCANREPORT`
- `CONTSCANREPORT`
- `MULTISCANREPORT`
- `ALLMATCHSCANREPORT`
- `FILDESREPORT`
- `INSTREAMREPORT`

The detection records bind `LargeFile.R04.Service.Detection.UNOFFICIAL` at
offset 19. The limit records bind the exact
`Heuristics.Limits.Exceeded.MaxFileSize` reason with no parser or matcher
work. The instream limit uses a 64-MiB stream cap so the result exercises
MaxFileSize admission rather than a wire-level StreamMaxLength rejection.

The capture also exposed and fixed an R04 producer defect: report probes use
transport status 0 after receiving a valid frame, so the producer now derives
the acceptance-record exit from the embedded report completion while still
requiring transport success. Development records are labeled
`sanitizer=development` rather than falsely claiming a Release build.
The direct report helper also emits the exact report-derived `FOUND` line and
match offset required by the service log verifier; a socketpair regression
covers that output alongside descriptor passing and framed-report parsing.

Verification:

- `python3 -B tools/largefile_development_service_capture_test.py` — passed.
- `python3 -B tools/largefile_acceptance_case_producer_test.py` — passed,
  including the transport-success/detection-outcome regression.
- `python3 -B tools/largefile_clamd_report_protocol_test.py` — passed,
  including exact detection-line and offset output.
- `python3 -B tools/largefile_acceptance_cases.py --manifest docs/largefile-capabilities.tsv --map docs/largefile-capability-case-map.tsv --records /private/tmp/clamav-r04-service-capture-20260907-final2/provenance/acceptance-cases.tsv --check-records --evidence-root /private/tmp/clamav-r04-service-capture-20260907-final2` — passed, 18 records.
- `git diff --check` — passed.
- Source capability manifest — passed, 597 entries.

Evidence hashes:

These hashes identify the evidence bundle exactly as captured; subsequent
edits to this receipt are documentation changes and do not retroactively
change the capture-time source identity.

- source manifest: `88d24b0fbaaad8489050bb9ac528bcf17d4c1b9c160e22865ae360f364bbff27`
- build identity: `c1283aaee0621b3899d0ad6ac717068091759a951920f25a647b114eca4e6c08`
- CMake cache: `e2a9a9c78ab10e1058614aec90269f6c4e4a0c890f30b07edc4834ad5d918fd7`
- acceptance records: `dfd07fcfd035c94562dcd9ae20ec2adc0d40b414b7d5700a5ecbb5d15f37dbd9`

This evidence is intentionally not fed into authoritative readiness: it uses
an ARM64 Debug build and 64-MiB development limits, so the certified Linux
x86-64 Release/sanitizer/full-size service run remains required.

State: `development-verified`; certified qualification remains blocked.
