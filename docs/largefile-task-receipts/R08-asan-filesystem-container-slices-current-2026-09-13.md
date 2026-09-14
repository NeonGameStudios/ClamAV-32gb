# Task receipt: R08 current-source filesystem/container ASan/UBSan slices

Task ID / parent milestone: `R08` / `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.
The Check runner used `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`,
`CK_FORK=yes`, `CK_DEFAULT_TIMEOUT=300`, and `T=60`.

The following slices completed successfully:

- TAR: `tar` 9/9, `tar_map` 3/3, `tar_member` 9/9, `tar_corpus` 1/1
- CPIO: `cpio` 2/2, `cpio_crc` 4/4, `cpio_numeric` 4/4, `cpio_map` 7/7
- ISO: `iso` 1/1, `iso_map` 19/19
- UDF: `udf_map` 14/14, `udf_corpus` 1/1 (`udf` selected zero checks)
- Partition formats: `partition_map` 5/5, `gpt` 9/9, `mbr` 12/12

Total: 100 substantive checks, 0 failures, 0 errors. The runner output
contained no ASan, UBSan, LeakSanitizer, or runtime-error diagnostics.

This is ARM64 development evidence only. These slices do not supply the
roadmap's capability-specific acceptance records, full-size/materialized
fixtures, production CVD/service, certified Linux x86-64, resource/fanotify,
independent format-8, Sonic1, or final release evidence. No capability was
promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
