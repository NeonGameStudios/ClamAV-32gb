# Task receipt: R05 independent sparse-boundary oracle

Task ID / parent milestone: `R05` / `R00`

This slice strengthens fixture admission only. It does not claim a live
scanner run or release qualification.

The boundary corpus generator now invokes
`tools/largefile_boundary_corpus_check.py` before reporting success. The
independent checker requires the reviewed eleven-row manifest, rejects unsafe
or extra rows, checks each logical size and 64-byte marker window with
`pread`, requires sparse allocation metadata, and detects changes while the
fixture is being inspected. It reads the marker windows only; it does not
traverse the holes in the 32-GiB sparse fixtures.

The runtime evidence verifier reruns the checker against retained corpus
fixtures and retains the checker as provenance. The regression suite covers a
valid sparse fixture plus manifest-row, marker, and extra-row tampering. The
runtime evidence regression now generates and checks the complete sparse
boundary corpus before exercising its synthetic evidence cases.

The new `tools/largefile_zip_late_member.py` generator creates a deterministic
stored ZIP whose final member contains one late marker. It fixes creator,
permission, timestamp, and storage metadata so repeated builds have identical
bytes. Its independent raw
EOCD, central-directory, local-header, CRC, member-range, and marker oracle
does not use `zipfile` for validation. `largefile_zip_late_member_test.py`
covers reproducible bytes, valid binding, empty-archive rejection, marker
tampering, and truncation rejection.

The oversized FILDESREPORT probe now supports explicit `AlertExceedsMax=off`
and `AlertExceedsMax=on` bindings. The service qualification sequence runs the
alerts-on probe, restarts clamd with alerts disabled for the alerts-off probe,
restores the certified alerts-on profile, and atomically combines both
mode-bound reports into a `clamav-service-oversize-both-v1` evidence bundle.
The workload verifier dispatches that bundle through the same fail-closed
oversized-report validator, so a single-mode or mismatched-mode report cannot
stand in for the two-mode control.

Verified commands:

- `python3 -B tools/largefile_boundary_corpus_check_test.py` — 4 tests passed.
- `sh tools/largefile_boundary_corpus.sh <temporary-directory>` — generated
  and independently verified all 11 rows, including `32g-head.bin` and
  `32g-edge.bin`.
- `sh tools/largefile_runtime_evidence_check_test.sh` — passed, including the
  new retained-corpus verification.
- `python3 -B tools/largefile_zip_late_member_test.py` — 5 tests passed.
- `python3 -B tools/largefile_service_oversize_test.py` — 22 tests passed,
  including both AlertExceedsMax modes and bundle publication.

Remaining R05 work: execute the prepared current-source FILDESREPORT
oversized run with alerts on and off, plus produce fully materialized
release-family fixtures. Those require the unavailable certified Linux x86-64
build/runner and are not substituted by this sparse-oracle control.

Runner-boundary revalidation:

- The prepared live sparse `FILDESREPORT` probe was attempted against the
  current ARM64 daemon in disposable Docker with `MaxFileSize=32G` and
  `MaxScanSize=64G`. The daemon loaded its limits, then rejected startup with
  `ERROR: Large-file daemon admission failed: certified large-file daemon
  admission is limited to Linux x86-64`; no socket, scan, or evidence record
  was accepted from that attempt.
- This confirms the remaining live oversize step is runner-bound, not a reason
  to weaken the exact 32-GiB contract or relabel the ARM64 result.

Materialized 32-GiB edge development run on Sonic1 (2026-09-09 UTC):

- Capacity gate: Linux x86-64 host with 66,800,082,944 bytes RAM,
  63,002,746,880 bytes available RAM, 144,445,280,256 bytes available in
  `/tmp`, 12 CPUs, and an unlimited container memory cgroup.
- Fixture: `/tmp/clamav-materialized-edge-20260909/32g-edge.bin`, written in
  four bounded segments rather than fallocate-backed storage. Independent
  verification reported `size=34359738368`, `allocated=34359742464`,
  `first_hole=34359738368`, and the expected marker
  `CLAMAV-LF-32G-EDGE\\x00` at offset `34359738304`.
- Image: `clamav-32gb:dev-current`, digest
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
  The scan used the repaired isolated build, the NDB marker oracle, and an
  explicit empty CUD certificate directory prerequisite.
- The named container `clamav-edge-scan-20260909` exited `1` after scanning
  the complete fixture. Its bounded debug output reported
  `LargeFile.POC.32g-edge.UNOFFICIAL matched at 34359738304` and the expected
  detection line.
- Structured report: `/tmp/clamav-materialized-edge-20260909/out/32g-edge.jsonl`,
  SHA-256
  `0898bbddb3df47ae3906286cb6470844cb5a47afbefe20b029b0719d8fc729fa`.
  It records `status=1`, `verdict=2`, `completion=DETECTION_TERMINATED`,
  `root_size=34359738368`, `logical_bytes=34359738368`,
  `matcher_bytes=34368129024`, `elapsed_ms=109169`,
  `last_alert=LargeFile.POC.32g-edge.UNOFFICIAL`, and
  `last_alert_offset=34359738304`.
- The engine debug hash for the scanned fixture was
  `0d5226ec60cd03781106de6d2cee6ff5fcf2101f95d181c14e9abf5bed593429`.

This is retained development evidence for the materialized edge case. It is
not promoted into the R04 structured acceptance records or release readiness:
the remote image still came from the isolated repaired-source graph rather
than a frozen, complete current-source checkout, and the remaining family,
FILDESREPORT, and dependency-bound checks are still outstanding.
