# R08 TNEF empty-title format receipt — 2026-09-13

## Scope

Close the current-source TNEF gap where a zero-length `attAttachTitle`
attribute was accepted as clean without reaching the attachment parser's
existing `length <= 0` format check.

The [MS-OXTNEF ABNF description](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxtnef/b03b5704-ef54-4390-b981-dc78f8e79a05)
defines attribute data as octets; an attachment title is a string value and a
zero-length attribute cannot carry its required string terminator.

## Change

`libclamav/tnef.c` now rejects a zero-length attachment title with
`CL_EFORMAT`, marks the recognized scan incomplete with the explicit reason
`TNEF attachment title is empty`, and preserves the non-cacheable result.

`unit_tests/check_clamav.c` adds and registers
`test_tnef_empty_attachment_title_is_fail_visible`, which verifies the return
status, sticky incomplete reason, and cache taint.

## Verification

Before the fix, the new regression reproduced the gap in the Release build:
the parser returned `CL_CLEAN` where `CL_EFORMAT` was required.

After the fix:

- Release focused TNEF group: `20/20` passed.
- ASan/UBSan focused TNEF group: `20/20` passed.
- ASan/UBSan run used `ASAN_OPTIONS=detect_leaks=0` and
  `UBSAN_OPTIONS=halt_on_error=1`; no sanitizer diagnostics were emitted.
- Full `sh tools/largefile_source_guards.sh`: passed.
- Generated inventory freshness diff: passed.
- `git diff --check`: passed.

The parser remains `pending`; this receipt does not promote a capability or
claim certified x86-64, production-CVD/service, Sonic1, or complete parser-
family qualification.

## Reproduction commands

```text
docker exec clamav-current-rust-build-20260911 cmake --build /tmp/clamav-release-current-20260913 --target check_clamav -j2
docker exec clamav-current-rust-build-20260911 sh -lc 'cd /tmp/clamav-release-current-20260913 && CK_RUN_SUITE=cl_suite CK_RUN_CASE=tnef T=1200 ctest --output-on-failure -R "^libclamav$"'
docker exec clamav-current-rust-build-20260911 cmake --build /tmp/clamav-asan-current-20260912 --target check_clamav -j2
docker exec clamav-current-rust-build-20260911 sh -lc 'cd /tmp/clamav-asan-current-20260912 && ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 CK_RUN_SUITE=cl_suite CK_RUN_CASE=tnef T=1200 ctest --output-on-failure -R "^libclamav$"'
```

## Evidence hashes at close

Hashes at close:

```text
bfc611a789e2cff3b15c2a9a1288df7e0090f2a75a1bffa586bf856898941158  libclamav/tnef.c
4935b8bc87d86e0c0eafb41fb2be3203960718251899f5fc201deb11b72e3adc  unit_tests/check_clamav.c
374e7dcdab6a64fd2d4f520eb45c58c14d451d9347a162773e94b12566bffc7c  tools/largefile_source_guards.sh
a2f152241aecd4068752008afe92b3aabd39ed23da5e37d4b573d517288a3c25  docs/largefile-capabilities.tsv
507ed5c54df9d2853ae2eb316d05ec24d527af8943183a302967f25d1cd31208  docs/largefile-inventory.tsv
3f6775f1ad79be1cf76a784aeaca0c3caae26aa7816a9c5bea2b8dc11497069b  32gb-current-snapshot.md
```
