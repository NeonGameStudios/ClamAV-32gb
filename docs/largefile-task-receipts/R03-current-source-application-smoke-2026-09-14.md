# R03 current-source application smoke — 2026-09-14

Task ID / parent milestone: `R03` / `R04`, `R10`

The retained ARM64 Release binary was exercised from the dirty canonical tree at HEAD `8e837b88c89874b180a1a25f22d287f7d6be29db`. The final current-source manifest contains 1,697 entries and has SHA-256 `7e4ba6ea8723508033f05cfa618b2a337148f7716e9d5442f9253d8be8910f20`. No commit, push, workflow action, capability promotion, software installation, or usage reset was performed.

## Runtime controls

The smoke used a temporary HDB database generated from the input's independently calculated MD5 and removed all temporary files after the run:

* Input bytes: `clamav runtime smoke\n`; SHA-256 `ab26d22c1a7f84f9aa65805bd3b26a145e6bafccd3774c58ae333efea5deb9a6`.
* HDB line: `d4300de57b6ad9cb7674a8b6bc797e82:21:LargeFile.Runtime.Smoke`; SHA-256 `0d0e2c6e27980204ac2b2bccf6802a89335cbbdf89f83b7f8ec83455d2ace1d9`.
* Checked-in certificate directory: `/src/unit_tests/input/signing/verify`.

Release `/tmp/clamav-release-current-20260913/clamscan/clamscan` produced the expected exact detection with exit 1 and alert `LargeFile.Runtime.Smoke.UNOFFICIAL FOUND`. The same input with `--report-json` also exited 1 and produced a structured record with `status=1`, `verdict=2`, `completion=DETECTION_TERMINATED`, `root_size=21`, `logical_bytes=21`, `matcher_bytes=21`, `files_scanned=1`, and `last_alert=LargeFile.Runtime.Smoke.UNOFFICIAL`. The JSON SHA-256 was `08261a4ce5510541518a17cb6b5aca80b3eccca11fd02b817047cbc40cb6dd97`.

The Release binary also scanned `/src/README.md` with the checked-in `unit_tests/input/clamav.hdb` and returned `OK` with exit 0. Clean-output SHA-256: `eacd6f881fbda956592272da71197f09dc3debeb7bb3cf02d4311c3f11330e03`.

## Scope

This proves the current Release application can load a database, complete a clean scan, detect an exact custom signature, and emit structured JSON. It is not full R04 capability evidence or R11/R12/R14 release qualification: certified Linux x86-64, exact/materialized 32-GiB edges, sanitizer service parity for this smoke, production CVDs, resource/fanotify, Sonic1, complete capability-case records, and final readiness remain open.

State: `development-verified`
