# Task receipt: R03 bounded sanitizer corpus follow-up — 2026-09-13

Task ID / parent milestone: `R03` / `R08`.

## Scope

Exercise additional current-source parser, corpus, map, and API paths under the
existing C ASan/UBSan build while the unfiltered `libclamav` wrapper remains
too slow for the ARM64 development runner. No source behavior changed in this
verification slice.

## Evidence

Using the preserved `clamav-current-rust-build-20260911` runner and
`/tmp/clamav-asan-current-20260912`, each bounded invocation used:

```text
CK_RUN_SUITE=cl_suite CK_RUN_CASE=<case> ctest --test-dir /tmp/clamav-asan-current-20260912 --output-on-failure -R '^libclamav$'
```

All 25 CTest invocations passed `1/1`, with no ASan/UBSan diagnostics:

- Corpus/parser: `pdf_corpus` (3.39s), `xar_corpus` (5.58s),
  `pe_corpus` (3.16s), `gif_corpus` (3.63s), `rust_lha` (12.24s),
  `pdf_map` (12.77s), `xar_subdoc` (6.23s), `xar_metadata` (8.77s),
  `hwp3_corpus` (7.10s), `hwpole2_corpus` (6.92s), `autoit_corpus` (6.11s),
  `7z_sfx_corpus` (6.53s), `tiff_large` (8.59s), `png_corpus` (6.36s),
  `jpeg_corpus` (6.36s).
- API/map: `cl_callback_api` (11.06s), `hash_stream` (6.41s),
  `cvd_api` (19.38s), `cvd_info` (6.94s), `cryptff` (9.83s),
  `cryptff_api` (5.17s), `elf_map` (23.63s), `elf_corpus` (6.36s),
  `tnef_map` (9.16s), `graphics_api` (6.32s).

The source-manifest helper was rerun after the tests: 1,697 entries,
SHA-256 `5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`.

## Public scan-API follow-up

After the corpus slice, the same current-source sanitizer build ran the
broader `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_scan_api` TCase. The CTest log
reports `836` checks, zero failures, and zero errors; CTest passed `1/1` in
`1,039.67` seconds. The run completed under the configured timeout and emitted
no ASan/UBSan diagnostics.

## Bytecode runtime follow-up

The same build then ran the correctly selected `bytecode/arithmetic` TCase.
The CTest log reports `52` checks, zero failures, and zero errors; CTest passed
`1/1` in `68.74` seconds with no ASan/UBSan diagnostics. The earlier selector
attempt using `cl_suite/arithmetic` selected no tests and is not counted.
This covers the existing development bytecode runtime controls only; it does
not satisfy the separate R07 requirement for an independently compiled
format-8 fixture exercising v2 globals and interpreter/JIT execution.

## Additional parser-family follow-up

Ten more bounded invocations against the same current-source ARM64 sanitizer
build passed `1/1`, with no ASan/UBSan diagnostics: `mail` (75.81s),
`mail_partial` (48.19s), `mhtml` (73.95s), `tar` (40.16s),
`tar_member` (85.51s), `iso` (45.00s), `udf_corpus` (55.07s),
`apm_corpus` (40.75s), `gpt_corpus` (52.36s), and `zip_sfx` (53.13s).
These cover additional MIME, archive, filesystem, partition, and SFX corpus
paths; they are development evidence and not release qualification.

## Qualification boundary

This is current-source ARM64 development sanitizer evidence only. It does not
qualify the 601 capability rows or replace the unfiltered Check suite,
certified Linux x86-64, exact 32-GiB/materialized edges, production CVD and
service evidence, privileged fanotify, Sonic1, independent format-8 bytecode,
or final release qualification. The current readiness status remains
`601 total / 0 qualified / 147 bounded / 440 pending / 14 allowlisted
unsupported / 587 blocked`.

No software was installed, no usage reset was used, and no GitHub workflow,
commit, or push was performed.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`.
