# Task receipt: R08 current-source executable parser ASan/UBSan slices

Task ID / parent milestone: `R08` / `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.
The Check runner used `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`,
`CK_FORK=yes`, `CK_DEFAULT_TIMEOUT=300`, and `T=60`.

The following slices completed successfully:

- ELF: `elf_map` 17/17, `elf_corpus` 1/1, `elf` 4/4
- PE: `pe32plus_common` 8/8, `pe_map` 18/18, `pe_corpus` 1/1
- Mach-O: `macho` 12/12, `macho_fat` 3/3, `macho_sections` 1/1,
  `macho_corpus` 2/2

Total: 67 checks, 0 failures, 0 errors. The runner output contained no ASan,
UBSan, LeakSanitizer, or runtime-error diagnostics.

This is ARM64 development evidence only. These slices do not supply the
roadmap's capability-specific acceptance records, full-size/materialized
fixtures, production CVD/service, certified Linux x86-64, resource/fanotify,
independent format-8, Sonic1, or final release evidence. No capability was
promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
