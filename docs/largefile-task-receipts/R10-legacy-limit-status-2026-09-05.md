# R10 legacy limit-status contract slice

Task ID / parent milestone: `R10` / `R00`

Scope: preserve configured scan-limit outcomes through the public legacy scan
wrappers without relabelling them as malware or clean success.

Prerequisites verified:

- Canonical source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`.
- Branch: `largefile-roadmap-qualification`.
- Current-source ARM64 static test binary rebuilt in the disposable
  `clamav-largefile-local-toolchain2:latest` container.
- No host software installation was performed.

Change made:

- Added one shared legacy status mapper in `libclamav/scanners.c` and applied
  it to `cl_scandesc`, `cl_scandesc_callback`, `cl_scanmap_callback`,
  `cl_scanfile`, and `cl_scanfile_callback`.
- Strong detections and ordinary PUA verdicts still return `CL_VIRUS`.
- The configured-limit alerts now retain their exact public status:
  `MaxFileSize`/`MaxScanSize` -> `CL_EMAXSIZE`, `MaxFiles` -> `CL_EMAXFILES`,
  `MaxRecursion` -> `CL_EMAXREC`, and `MaxScanTime` -> `CL_ETIMEOUT`.

Evidence:

- `cmake --build /tmp/clamav-largefile-static-build --target check_clamav -j2`:
  exit 0.
- The current-source `clamscan` target relinked successfully; `clamscan
  --version` reported `ClamAV 1.5.3-largefile-devel`, and stdin scanning with
  the repository NDB signature detected
  `NDB.Clamav-Unit-Test-Signature.UNOFFICIAL` with the expected exit code 1.
- Broad current-source `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api` run:
  510 checks, 38 failures, 3 errors. The prior run had 39 failures and 3
  errors; the legacy max-file-size conversion failure is no longer reported.
- The remaining broad failures are independent injected-failure and fixture
  cases; this slice does not claim them as resolved.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` and
  `--check-records`: passed (`597` capabilities, `0` records).
- `sh tools/largefile_source_guards.sh`: passed.
- `git diff --check`: passed.

Full-size/certified evidence produced, or explicitly not run: no Linux x86-64
Release/sanitizer evidence, exact 32-GiB materialized run, production-CVD,
service, on-access, or Sonic1 qualification was produced. No capability was
promoted to qualified by this receipt.

State: `development-verified`; release readiness remains blocked.
