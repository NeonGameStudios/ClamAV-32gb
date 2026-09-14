# Task receipt: R08 current-source archive and compression ASan/UBSan slices

Task ID / parent milestone: `R08` / `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.
The Check runner used `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`,
`CK_FORK=yes`, `CK_DEFAULT_TIMEOUT=300`, and `T=60`.

The following slices completed successfully:

- DMG/HFS+: `dmg` 12/12, `hfs_inline` 2/2, `hfs_map` 25/25,
  `hfs_fork` 2/2
- SIS: `sis` 1/1, `sis_structure` 3/3, `sis_member` 1/1, `sis_map` 3/3
- AutoIt: `autoit_map` 9/9, `autoit_corpus` 1/1, `autoit_sfx` 1/1
- ZIP/RAR/CAB: `zip_sfx` 5/5, `rar` 11/11, `cabsfx` 3/3
- XZ: `xz` 4/4, `xz_corpus` 1/1, `xz_trailing` 1/1
- Legacy/compressed: `binhex_map` 15/15, `mydoom_map` 5/5,
  `bz_map` 5/5, `bz_core` 10/10

Total: 120 checks, 0 failures, 0 errors. The runner output contained no
ASan, UBSan, LeakSanitizer, or runtime-error diagnostics.

This is ARM64 development evidence only. These slices do not supply the
roadmap's capability-specific acceptance records, full-size/materialized
fixtures, production CVD/service, certified Linux x86-64, resource/fanotify,
independent format-8, Sonic1, or final release evidence. No capability was
promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
