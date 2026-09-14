# Task receipt: R08 current-source XAR, SFX, and Office-entry ASan/UBSan slices

Task ID / parent milestone: `R08` / `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.
The Check runner used `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`,
`CK_FORK=yes`, `CK_DEFAULT_TIMEOUT=300`, and `T=60`.

The following substantive slices completed successfully:

- XAR: `xar_map` 3/3, `xar_corpus` 3/3, `xar_subdoc` 1/1
- APM: `apm_map` 3/3, `apm` 8/8, `apm_corpus` 1/1
- SFX: `7z_sfx` 3/3, `7z_sfx_corpus` 1/1, `ishield_map` 4/4,
  `ishield_sfx` 1/1
- Office entries: `ole10_entry` 7/7, `ppt_entry` 9/9, `ooxml_entry` 3/3
- Binary data: `binary_data` 1/1

Total: 48 substantive checks, 0 failures, 0 errors. The `digital` and
`assorted functions` selectors contained zero checks and were not counted.
The runner output contained no ASan, UBSan, LeakSanitizer, or runtime-error
diagnostics.

This is ARM64 development evidence only. These slices do not supply the
roadmap's capability-specific acceptance records, full-size/materialized
fixtures, production CVD/service, certified Linux x86-64, resource/fanotify,
independent format-8, Sonic1, or final release evidence. No capability was
promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
