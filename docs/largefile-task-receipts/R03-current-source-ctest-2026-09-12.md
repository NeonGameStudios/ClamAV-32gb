# Task receipt: R03 current-source CTest matrix — 2026-09-12

Exact scope: current-source ARM64 Release CTest verification for the
large-file roadmap build. This receipt records a verification slice only; it
does not promote any capability or claim release qualification.

## Starting identity

- Repository: `<repository-root>`
- Branch: `largefile-roadmap-qualification`
- HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db`
- Working tree: dirty and preserved; no unrelated changes were reverted.
- Current-tree source-manifest SHA-256:
  `439eef3f46a381e4dbe6b185d3d7336b5b3cdda867ee5d8d734870e4e98811d9`
- Build container: `clamav-current-rust-build-20260911`
- Build image: `rust:1.97-bookworm`
- Build directory: `/tmp/clamav-release-current-20260912`
- Build type: `Release`
- Enabled features verified in `CMakeCache.txt`: `ENABLE_CLAMONACC=ON`,
  `ENABLE_MILTER=ON`, and `ENABLE_UNRAR=ON`.

## Commands and results

The exact 16 registered CTest targets were run in three bounded invocations
to avoid resource pressure from a single large process group:

1. `ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure -R
   "^(libclamav|libclamav_rust|clamd)$"` — exit `0`, `3/3` passed in
   `120.48` seconds.
2. `ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure
   -I 2,11,1` — exit `0`, `10/10` passed in `25.22` seconds.
3. `ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure
   -R "^(clamscan|freshclam|sigtool)$"` — exit `0`, `3/3` passed in
   `56.06` seconds.

The union is the complete registered matrix: `libclamav`,
`largefile_poc_fail_closed`, `largefile_source_guards`,
`largefile_runtime_evidence_check`, `largefile_acceptance_case_schema`,
`largefile_development_acceptance_capture`, `largefile_clamscan_admission`,
`largefile_clamd_report_protocol`, `largefile_zip_late_member`,
`clamav_milter_quota`, `clamav_milter_protocol`, `libclamav_rust`, `clamscan`,
`clamd`, `freshclam`, and `sigtool`.

## Build identities

The freshly inspected Release executable hashes were:

- `clamonacc`: `8a7aadfc252d617c24537b76fb3b4cc72e3451b4292d46da41eebcd5c42ec12`
- `clamd`: `e663583968dfe7b91da705b0fc913759d8810ec512195991b6f11a5e8cce68db`
- `clamdscan`: `7ec20b8b5d1a0ceec6f005a50090e5ecdb2e79725018638086f2f88cc6735a3e`
- `clamscan`: `b085b063e507da218d1ea5ed3436a91a7572bcf11462c4ec9ff3daa17eaa99c6`

## Boundary

This is current-source ARM64 development evidence. It does not establish the
roadmap's certified Linux x86-64 runner, C and Rust sanitizer parity,
production CVD/database behavior, fully materialized 32-GiB edge workloads,
PCRE phase measurements, queue stress/resource proof, or real fanotify
permission-event evidence. The authoritative readiness gate remains blocked;
the next release-bound work must use an authorized certified runner and
capability-specific acceptance records.

State: `development-verified`.

## Current-source revalidation after R13 on-access changes

The same 16 registered CTest targets were rerun against the current mounted
source and the existing ARM64 Release build after the inotify hierarchy-state
hardening. The invocations remained bounded and serial:

1. `ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure
   -R "^(libclamav|libclamav_rust|clamd)$"` — exit `0`, `3/3` passed in
   `150.07` seconds.
2. `ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure
   -I 2,11,1` — exit `0`, `10/10` passed in `108.38` seconds.
3. `ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure
   -R "^(clamscan|freshclam|sigtool)$"` — exit `0`, `3/3` passed in
   `123.93` seconds.

The current source-manifest SHA-256 is
`825ae463132f8c095a87fd77702e09f4f6b3a815e1b04dc308da033a8b194f1b`, and the
rebuilt `clamonacc` SHA-256 is
`b2d0ef4ba1725d5dcdc21dbd772b32b13d201f475ffea2b6be98726eb29393bd`.

State remains `development-verified`; the matrix still does not establish
certified x86-64, full-size materialized workloads, sanitizer parity,
production-CVD, PCRE/queue resource evidence, or real fanotify permission
events.

## Current-source rebuild and full CTest revalidation

After the R04 service per-case resource integration, the mounted current
source was reconfigured and rebuilt in the existing `rust:1.97-bookworm`
ARM64 container. `cmake --build /tmp/clamav-release-current-20260912 -j2`
completed successfully, including `clamd`, `clamdscan`, `clamscan`,
`clamonacc`, `clamav-milter`, `sigtool`, `clambc`, and `check_clamav`.

The complete configured CTest invocation
`ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure`
passed `24/24` in `203.56` seconds. This included the library, Rust, CLI,
daemon, freshclam, sigtool, milter, acceptance/evidence, procfs, OOM, and
service-evidence suites. The existing ARM64 container was stopped afterward.

The current source-manifest SHA-256 is
`f2db32e87842c846da4d8064bc546930f7d7d9787a2ec676db12e07b6e9d0faf`.
This remains development verification: it does not replace the certified
Linux x86-64, full-size, sanitizer, production-CVD, Sonic1, PCRE/queue,
fanotify-permission, or final release gates.
