# R02/R04/R10 Sonic1 v17 service matrix — 2026-09-27

Task IDs / parent milestones: R02, R04, R10; development-only daemon/client
outcome parity. No capability status was promoted.

## Candidate and source binding

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
  image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Build: `/qualification/build-v17-0e011be4-release`, Release configuration;
  its CMake source directory is `/qualification/src-v17-0e011be4` and its
  `CLAMAV_SOURCE_COMMIT` is the source-manifest digest below.
- Source manifest SHA-256:
  `0e011be4f9c399c62b752efc574cbbe1c893735184088d05e497d1e2ce0699dc`.
- Build identity SHA-256:
  `fa32eb93638d8242716b9a732a3a83a592b08efaf5d35db8b8e60086cdb5a82c`.
- `clamd` SHA-256:
  `cef0d30709df0ce4c9162f4fb2005f62b640fe3736ab5a7ce68ae9fd8cdbbe93`.
- `clamdscan` SHA-256:
  `6e22ab27daed6a9b510f04e13ff1c2292c8e7935c1dc9135edaf4d7b856eac15`.

The container's separate read-only `/src` mount was checked and had source
manifest SHA-256 `f8bdf6d6f35eefccf0a80a14ba998ff744fab341c127a663dd356b85270bf57e`.
It did not match the v17 build source, so it was not used for this capture.

## Capture and verification

The first capture attempt was preserved at
`/qualification/r02-service-v17-20260927`. ClamD exited before readiness
because its configured temporary directory was on the container root
filesystem: 265,310,208 bytes were free, below the daemon's 4,362,076,160-byte
startup minimum. This was a test-storage placement failure, not a scan result.

The successful retry is at
`/qualification/r02-service-v17-20260927-retry1`. Its harness temporary root
was placed at `native-tmp/` on the disk-backed `/qualification` volume; no
application limits or source files were changed. The capture produced 36
records for six structured ClamD commands (`SCANREPORT`, `CONTSCANREPORT`,
`MULTISCANREPORT`, `ALLMATCHSCANREPORT`, `FILDESREPORT`, `INSTREAMREPORT`) and
six `clamdscan` modes (`default`, `fdpass`, `stream`, `multiscan`,
`stream-multiscan`, `fdpass-multiscan`). Each identity has a clean,
detection, and size-limit case.

Results: 12 `COMPLETE`, 12 `DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE`.
The detection cases use the exact development signature and oracle-bound
offset. All 36 records have `health=pass` and `cleanup=pass`. The capture's
own record validator passed, then an independent invocation of
`largefile_acceptance_cases.py --check-records --evidence-root ...` passed while
requiring all three mapped cases for each of the 12 capabilities.

- Acceptance record SHA-256:
  `f39c325b8d808b6377f8879a39f779bf438b7d077b5deb88b37db3bab1ffe57f`.
- Source-manifest artifact SHA-256 equals the v17 digest above.
- Capture command completed with exit 0 and reported
  `development service capture wrote 36 R04 records`.
- Independent acceptance-case validation completed with exit 0 and reported
  `large-file acceptance record schema passed (36 records)`.

## Qualification boundary

This is source-bound Linux x86-64 Release development evidence for current
daemon/client report and ingress behavior. Fixtures are small; databases are
locally generated test signatures. It does not establish exact/materialized
32-GiB service behavior, production-CVD coverage, sanitizer parity, measured
daemon RSS, privileged fanotify, full capability qualification, or release
readiness. The earlier failed attempt remains preserved separately. No
software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.

State: `development-verified; certified full-size and release evidence open`.
