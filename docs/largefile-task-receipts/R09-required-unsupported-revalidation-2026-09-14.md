# Task receipt: R09 required-unsupported revalidation — 2026-09-14

Task ID / parent milestone: `R09` / `R04`

Exact capability kind:id list: `matcher:rust-fuzzy-image-ffi-admission`,
`matcher:fuzzy-image`, `parser:CL_TYPE_AI_MODEL`, `parser:CL_TYPE_IGNORED`,
`parser:CL_TYPE_PYTHON_COMPILED`, `parser:CL_TYPE_RAR`, and
`parser:CL_TYPE_RARSFX`.

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`, HEAD
`8e837b88c89874b180a1a25f22d287f7d6be29db`, current tracked-source manifest
`19330bf9d99e14ef53661bf531e3cb402200abe0e395dbb44b49af86356a7667`.
The working tree was intentionally preserved as-is; this revalidation did not
create or remove source changes.

Prerequisites verified: the existing disposable ARM64 Docker container
`clamav-current-rust-build-20260911` was running with the current checkout
mounted at `/src`; the current-source Release and ASAN/UBSAN test binaries and
their CMake caches were already rebuilt; the checked-in CVD verification root
was bound through `CVD_CERTS_DIR`.

Owned files and excluded shared files: this receipt and two retained logs in
`/private/tmp`; no shared source, manifest, snapshot, case map, or workflow
file was edited.

Observed failing case and expected behavior: the seven R09 rows require the
focused behavior/failure pair to run against the current binary. A behavior
or failure control must preserve its declared detection, completion, parser,
resource, or unsupported result; it must not become clean through a generic
or stale test binary. This run was a revalidation after the current source
and warning-cleanup rebuilds.

Changes made: retained the Release output at
`/private/tmp/clamav-r09-required-unsupported-release-20260914.log` and the
ASAN/UBSAN output at
`/private/tmp/clamav-r09-required-unsupported-asan-20260914.log`.

Commands, exits, logs and identities:

- `CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=required_unsupported T=60`
  with `/tmp/clamav-release-current-20260913/unit_tests/check_clamav` — exit
  `0`, `57` checks, `0` failures, `0` errors.
- The same selector with
  `/tmp/clamav-asan-current-20260912/unit_tests/check_clamav`,
  `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, and
  `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1` — exit `0`, `57` checks,
  `0` failures, `0` errors.
- Release test binary SHA-256:
  `73300dbf222904af9cb924324ef83a76d017a4f4a105824804b899eb533ed2cb`.
- ASAN/UBSAN test binary SHA-256:
  `86437d38b423a6b3b51ef75066aefc9299c88a6e7f052bc157a508bb39314fe0`.
- Release CMake cache SHA-256:
  `f55a879d0fc1c609c1d64fa8dee8ba1b275d38d4e29de936419f8d2f77b56e57`.
- ASAN/UBSAN CMake cache SHA-256:
  `eee0b5df0c3520b0fc05d502ab3657232c26b66146f7571904151403a7852b43`.
- Both retained test logs have SHA-256
  `67465533ee8ad67773fe7f53c58859b753053756c706f71261c8a3e277dfa5d7`.

Development tests passed: the complete required-unsupported Check group ran
57/57 in both current-source ARM64 Release and ASAN/UBSAN configurations.
The sanitizer invocation emitted no ASAN, UBSAN, LeakSanitizer, or runtime
diagnostic. The existing source-guard and acceptance-map/schema checks remain
green.

Full-size/certified evidence produced, or explicitly not run: not run. The
host is ARM64 and is not the certified Linux x86-64 qualification profile;
these small focused checks do not establish 32-GiB materialized, service,
production-database, or final release evidence.

Remaining failures / next slice: R09 remains development-verified but pending
qualification. The next valid-content work must use independent full parser
corpora and capability-bound records; optional UnRAR extraction, certified
Linux x86-64 Release/sanitizer parity, full-size inputs, production CVDs,
service/ingress coverage, and the final readiness gate remain open. No
capability was promoted.

State: `development-verified; qualification-pending`.

