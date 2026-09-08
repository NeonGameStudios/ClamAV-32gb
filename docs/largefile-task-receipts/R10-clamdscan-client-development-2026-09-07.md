# R10 clamdscan client development receipt — 2026-09-07

## Scope

This receipt records current-source ARM64 development evidence for the
`clamdscan` client paths. It is not certified Linux x86-64 Release,
sanitizer, full-size, service, or fanotify qualification evidence.

Evidence directory:
`/private/tmp/clamav-r04-client-capture-20260907`

Build identity:

- `capture_kind=development-clamd-and-clamdscan`
- `build_type=Debug`
- `platform=Linux-aarch64`
- `sanitizer=development`
- `max_file_size=64M`
- `max_scan_size=64M`
- `max_temporary_size=64M`
- `clamd_sha256=408785d6d2e3112149749ca666e12b7832664c162ca006d01c2df0a60355708a`
- `clamdscan_sha256=a1980dc80f0710fd825a3c01cdc24485d024d43f3140a55af218ac281d322c0e`

## Captured cases

The evidence contains 24 schema-valid records:

- 18 direct daemon structured-report records: `SCANREPORT`,
  `CONTSCANREPORT`, `MULTISCANREPORT`, `ALLMATCHSCANREPORT`,
  `FILDESREPORT`, and `INSTREAMREPORT` across clean, detection, and limit
  fixtures.
- 6 client records: `clamdscan --fdpass` and `clamdscan --stream` across the
  same three outcomes.

The client records bind the client capability and mode explicitly. Detection
records carry `LargeFile.R04.Service.Detection.UNOFFICIAL` at offset 19.
Limit records carry `LIMIT_INCOMPLETE`, exit 2, and
`Heuristics.Limits.Exceeded.MaxFileSize`.

## Defect fixed during capture

The first fdpass limit run exposed a real client defect: the client-side
MaxFileSize refusal was emitted as a generic `RESOURCE_FAILURE` report with
zero root size and no configured limits. The fix adds a shared fdpass size
preflight result, preserves `CL_EMAXSIZE` through the structured client path,
and writes a populated fallback report with the file size, limits, binary
file type, and exact MaxFileSize reason. Legacy non-report fdpass return
behavior remains unchanged.

The capture harness also removes each per-case report before launching
`clamdscan`, preventing its append-mode report writer from duplicating records
when a development run is retried.

Follow-on source audit found one additional ownership gap in the structured
serial client path: a failed `dsreport()` returned to callback cleanup without
closing its daemon socket. `serial_callback()` now closes that socket before
serializing the failure report and releasing the action source. This patch was
syntax/guard verified separately and was not relinked into the pre-existing
ARM64 capture binaries.

## Verification

- `python3 -B tools/largefile_development_service_capture_test.py` — 3/3
  passed.
- Disposable Docker build of `clamd`, `clamdscan`, and `check_clamd` — passed.
- Focused CTest `largefile_clamscan_admission` — 1/1 passed.
- Filtered `check_clamd` client-accounting group — 7/7 checks passed.
- `python3 -B tools/largefile_acceptance_cases.py --check-records ...` — 24
  records passed schema, artifact, and hash validation.
- `git diff --check` — passed.
- `sh tools/largefile_source_guards.sh` — passed, including the regenerated
  inventory, 597-row capability map, readiness controls, and focused Python
  checks.
- `python3 -B tools/largefile_clamd_report_protocol_test.py` — passed.
- `python3 -B tools/largefile_service_result_check_test.py` — 10/10 passed.
- `python3 -B tools/largefile_service_workload_check_test.py` — 21 tests
  passed, with the two expected non-Linux filesystem skips.

## Follow-on current-source capture

A fresh disposable ARM64 run of
`tools/largefile_development_service_capture.py` completed with exit 0 and
wrote 24 records under `/private/tmp/clamav-r10-development.HnUMyf`. The
records were independently rechecked with the capability map and artifact
bindings:

```text
python3 -B tools/largefile_acceptance_cases.py --manifest docs/largefile-capabilities.tsv --map docs/largefile-capability-case-map.tsv --records /private/tmp/clamav-r10-development.HnUMyf/provenance/acceptance-cases.tsv --check-records --evidence-root /private/tmp/clamav-r10-development.HnUMyf
large-file acceptance record schema passed (24 records)
```

The capture covers all 18 direct daemon structured-report combinations plus
6 `clamdscan` fdpass/stream combinations, each across clean, detection, and
size-limit outcomes. The current source-manifest SHA-256 is
`43fe9f6bf9ea23068000ba5b0b86b37e026a7b7afc0fec51a14ec6a2f8d29260`, the
build identity SHA-256 is
`3b4d5cea27cc0a949d397cd9ea8def42863919d1389b194c93955e5eceb0a096`, the
CMakeCache SHA-256 is
`e2a9a9c78ab10e1058614aec90269f6c4e4a0c890f30b07edc4834ad5d918fd7`, and the
acceptance-record SHA-256 is
`99dc53d02a12b46f2c4ba9adb1c8c340a82073a39da83b0f12836922f4ed8b07`.

This remains ARM64 Debug development evidence with 64-MiB limits. It does
not qualify the 32-GiB contract, certified x86-64 Release/sanitizer behavior,
production CVDs, or on-access semantics.

Receipt hashes:

- `acceptance-cases.tsv`:
  `7f44b109ced1718d0d9ceeb2cd487ab768027a0a7f8dc5b6880ac735ac398715`
- `build-identity.txt`:
  `3b4d5cea27cc0a949d397cd9ea8def42863919d1389b194c93955e5eceb0a096`
- `source-manifest.txt`:
  `a85abb110ab1cf1d8c95b7a053407422ef495d20ad7dd9a4ac6e00bd87b3e08f`
- `oracle-clean.tsv`:
  `9353a44d294f79e50b2eb7ae4e3e27cae0a96404d688197957124109992d1e41`
- `oracle-detection.tsv`:
  `69245bec231bb36a5b65a31ab02c7fd66f8bbddf5d8838c15cc945c46dd82b34`
- `oracle-limit.tsv`:
  `23b5acb7b42bc91d09567d2a6f49a977de53be146b5a74702dacb310e9c0ff92`
