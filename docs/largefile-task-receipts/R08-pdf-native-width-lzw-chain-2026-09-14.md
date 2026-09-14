# R08 current-source PDF native-width LZW filter chain — 2026-09-14

Task ID / parent milestone: `R08` / `pdf-stream-over-1g`

The dirty canonical working tree remained at HEAD `8e837b88c89874b180a1a25f22d287f7d6be29db`; no commit, push, workflow action, or capability promotion was performed. The final current-source manifest contains 1,697 entries and has SHA-256 `7e4ba6ea8723508033f05cfa618b2a337148f7716e9d5442f9253d8be8910f20`.

## Observed gap and change

The PDF reader-based filter chain already handled input in bounded windows, but `pdf_decodestream_with_params_array()` rejected every supported multi-filter chain containing LZW when the declared input length exceeded `UINT32_MAX` or `CLI_MAX_ALLOCATION`. That pre-admission check was stale: the reader-based LZW decoder uses `size_t` coordinates, fixed input windows, quota-accounted output, and transactional rollback. The stale chain-only checks were removed. Unsupported or mixed chains still fail through the existing legacy boundary checks; the test was changed from an all-LZW supported chain to an LZW/FAX mixed chain to retain that negative contract.

The native-width regression now exercises a valid ASCIIHex-to-LZW chain with a logical input length of `UINT32_MAX + 1U` while the physical test backing remains one bounded input window. It verifies exact decoded bytes, output size, temporary reservation, and clean completion.

## Verification

Using the retained ARM64 `rust:1.97-bookworm` Docker container and checked-in certificate directory `/src/unit_tests/input/signing/verify`:

* Release build: `cmake --build /tmp/clamav-release-current-20260913 -j2` — exit 0.
* Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api T=60` — exit 0; 529 checks, 0 failures, 0 errors. `check_clamav` SHA-256: `ed8913956d1e9c837f2163ea8a0f89a4557165fb3ac96e9dff707b4f51ef5cf2`.
* ASan/UBSan build: `cmake --build /tmp/clamav-asan-current-20260912 -j1` — exit 0 after the parallel retry was killed by container exit 137.
* ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api T=60` with leak detection — exit 0; 529 checks, 0 failures, 0 errors. `check_clamav` SHA-256: `0e2b9c4c407ce65df03241bf2e6ff59ae55be9105bea93817db1e03c078ef7e0`.
* Sanitizer stderr log: `/tmp/clamav-asan-current-20260912/unit_tests/test-stderr.log`, SHA-256 `d9ed666f3787f24edeae8bde8a7aac7cbb2a23d9ac415e142b449673a49d330b`; no AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, or runtime-error diagnostics.
* `sh tools/largefile_source_guards.sh` — exit 0; the capability manifest, readiness regressions, snapshot/inventory freshness, PDF evidence schema, acceptance case/map/schema, runtime producer, fanotify, PCRE phase, service, protocol, boundary-corpus, and source-guard suites passed.

State: `development-verified`. Certified Linux x86-64, exact/materialized multi-gigabyte PDF streams, production CVD/service, resource/fanotify, Sonic1, complete parser-family, and final release qualification remain open.
