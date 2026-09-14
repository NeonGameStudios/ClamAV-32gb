# Task receipt: development service capture certificate default

Task ID / parent milestone: `R04` / `R10`.

Exact change: make the current-source development clamd service capture use
the repository test CA by default, matching the existing clamscan development
capture.

## Change

`tools/largefile_development_service_capture.py` now validates and resolves
`unit_tests/input/signing/verify` when `--cvd-certs-dir` is omitted. A supplied
certificate directory must be a real directory and cannot be a symlink. The
resolved directory is written into every generated clamd configuration, so a
fresh build does not accidentally use an absent system `/usr/local/etc/certs`
directory.

## Verification

- `python3 -B tools/largefile_development_service_capture_test.py` passed 8/8,
  including default-path and missing/symlink rejection cases.
- Current-source ARM64 Release `clamd` and `clamdscan` were rebuilt from
  `/tmp/clamav-release-current-20260912`.
- The capture was rerun without `--cvd-certs-dir` and wrote 24 R04 records to
  `/tmp/clamav-dev-service-20260912e`.
- The independent verifier passed:
  `python3 -B tools/largefile_acceptance_cases.py --check-records
  --records /tmp/clamav-dev-service-20260912e/provenance/acceptance-cases.tsv
  --evidence-root /tmp/clamav-dev-service-20260912e`.
- The captured source manifest is
  `099360edb0e59485e99ef2eff8ad0902cdd4bae7371fd96ed8fe06a28ddfffdf`.
- The captured build identity is
  `29f2cd22d7622402c42c6a92559533ae53923c6834913ec592b350e11759e44d`.
- Rebuilt binaries remain `clamd`
  `e663583968dfe7b91da705b0fc913759d8810ec512195991b6f11a5e8cce68db` and
  `clamdscan` `7ec20b8b5d1a0ceec6f005a50090e5ecdb2e79725018638086f2f88cc6735a3e`.
- The copied evidence is retained outside the source tree at
  `/tmp/clamav-dev-service-20260912e`.

This is development-only ARM64 evidence. It does not promote capabilities or
replace certified x86-64, sanitizer, full-size, production-CVD, resource,
Sonic1, and final release qualification.

State: `development-verified`; release qualification remains pending.
