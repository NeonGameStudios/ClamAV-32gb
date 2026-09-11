# Task receipt: five-issue current-source verification

Task ID / parent milestone: `R00` / roadmap follow-up across `R03`, `R04`,
`R06`, `R09`, and `R10`

Scope: rerun the current-source production-linked development controls for the
five roadmap issue areas after the R04 trust-root and R10 service-input
binding corrections. This receipt records development evidence only; it does
not promote a capability to release-qualified.

Canonical checkout and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

The source-manifest SHA-256 captured for this verification pass was
`31a688de68eef2396598c15ec3a449fe1b6b8d7e419648efbfe656f9f05cba61`.
The linked development binaries were retained in
`/private/tmp/clamav-32gb-docker-build` and had these SHA-256 values:

- `unit_tests/check_clamav`: `2f10f60f5a9a097bfe918cbfcfe1cdcfa27aeebe97996035867d787a4cf6cd91`
- `unit_tests/check_clamd`: `04c38af0dd24e8b75266a99709060a1045e701df0261d24c6fe2a94c6b4e674a`
- `clamd/clamd`: `dfa272199bffcab71bf20846942a2da836732b9a34e542e454dc5834c473dd8a`
- `clamdscan/clamdscan`: `afb168092fe9538ccfcd0e525fb1c592a28b3eb448de2f3710c7acc31609d2ac`

## Current-source linked cases

The disposable ARM64 container ran the production-linked Check targets from a
writable copy of the build tree. The existing repository test CA was supplied
to the CVD case through `CVD_CERTS_DIR`.

- `check_clamav`, `required_unsupported`: **38 checks, 0 failures, 0 errors**
- `check_clamav`, `rar`: **11 checks, 0 failures, 0 errors**
- `check_clamav`, `gif` (fuzzy-image/GIF path): **16 checks, 0 failures, 0 errors**
- `check_clamav`, `rust_onenote`: **2 checks, 0 failures, 0 errors**
- `check_clamav`, `onenote`: **2 checks, 0 failures, 0 errors**
- `check_clamav`, `rust_map`: **2 checks, 0 failures, 0 errors**
- `check_clamav`, `parser_regressions`: **4 checks, 0 failures, 0 errors**
- `check_clamav`, `descriptor_map`: **2 checks, 0 failures, 0 errors**
- `check_clamav`, `cvd_api`: **13 checks, 0 failures, 0 errors**
- `check_clamav`, `cvd_info`: **1 check, 0 failures, 0 errors**
- `check_clamd`, `option parser`: **31 checks, 0 failures, 0 errors**

These cases cover the R06 OneNote parser boundary, R09 required-unsupported
and fuzzy-image paths, R08 parser/descriptor/CVD boundaries, and R10 daemon
protocol parsing. They are development results on ARM64, not certified
Linux x86-64, sanitizer, full-size, production-CVD/service, or final-canary
evidence.

## Repository controls

Commands and results:

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 tests
  passed; 2 expected skips**
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability rows and
  acceptance controls passed**
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**
- `git diff --check` — **passed**
- `sh tools/largefile_release_readiness.sh --status` — **exit 1 as expected**:
  `597` total, `0` qualified, `143` bounded, `440` pending, `14` allowlisted
  unsupported, `0` unsupported required, and `583` blockers

## Remaining blockers

- R03 still lacks the authorized certified Linux x86-64 runner and current
  source transfer path.
- R04/R10 still lack certified full-size ingress/service records, including
  materialized 32-GiB edge cases and final canary evidence.
- R06 still needs materialized late-content proof and full parser quota
  qualification; the vendored reader-backed parser remains development-only.
- R09 still needs the independent RAR/RARSFX, fuzzy-image, and parser
  qualification evidence required by the roadmap, including sanitizer and
  certified execution.
- R07 remains blocked by the unavailable compatible independent format-8
  compiler/artifact.

No host software, remote execution, usage reset, GitHub workflow action,
commit, or push was used.

State: `development-verified`; release readiness remains blocked.
