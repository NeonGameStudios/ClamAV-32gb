# Task receipt: R06/R08 current-source API, text, and Rust ASan/UBSan slices

Task IDs / parent milestones: `R06`, `R08` / `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.
The Check runner used `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`,
`CK_FORK=yes`, `CK_DEFAULT_TIMEOUT=300`, and `T=60`.

The following slices completed successfully:

- API/fmap/CVD: `hash_stream` 1/1, `cvd_api` 13/13, `cvd_info` 1/1,
  `cryptff` 3/3, `cryptff_api` 1/1, `fmap_api` 4/4, `metadata_json` 1/1
- Text/documents: `text_encoding` 3/3, `html` 13/13, `screnc` 2/2,
  `script` 1/1, `structured_map` 6/6, `rtf` 1/1, `rtf_map` 16/16,
  `uuencode_map` 5/5, `uuencode_corpus` 1/1, `mhtml` 5/5
- Rust/MSXML: `rust_map` 2/2, `rust_lha` 10/10, `rust_alz` 2/2,
  `msxml` 10/10, `msxml_map` 3/3, `msxml_corpus` 1/1

Total: 105 checks, 0 failures, 0 errors. The runner output contained no
ASan, UBSan, LeakSanitizer, or runtime-error diagnostics.

This is ARM64 development evidence only. These slices do not supply the
roadmap's capability-specific acceptance records, full-size/materialized
fixtures, production CVD/service, certified Linux x86-64, resource/fanotify,
independent format-8, Sonic1, or final release evidence. No capability was
promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
