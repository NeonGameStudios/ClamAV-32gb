# R08 — PDF empty extracted-object MaxFiles accounting

Date: 2026-09-13 UTC  
Status: implemented and locally verified; not release-qualified

## Gap and change

`pdf_extract_obj()` skipped descriptor admission when a successfully
materialized object decoded to zero bytes. An empty PDF stream also returned
before the shared nested-child path. Both paths now route the empty output
through `cli_magic_scan_desc_type_reserved()`, so the logical child consumes
the inclusive `MaxFiles` slot and inherits the existing cache-invalidation
behavior. Zero-byte output skips PDF bytecode/content hooks that require a
mappable payload.

## Regression evidence

- `test_pdf_empty_extracted_object_counts_toward_maxfiles`: Release PDF TCase
  passes 26/26; the corrected case advances `scannedfiles` from 1 to 2.
- `test_pdf_empty_stream_counts_toward_maxfiles`: Release PDF TCase passes
  26/26; the corrected case advances `scannedfiles` from 1 to 2.
- GCC ASan/UBSan PDF TCase passes 26/26 with
  `ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1`; no sanitizer
  diagnostics were emitted.
- The Release `clamscan` executable rebuilt successfully, reports
  `ClamAV 1.5.3-largefile-devel`, detects the checked-in HDB test executable,
  and reports `/src/README.md: OK` with the same database and certificate
  directory.

## Repository evidence

- Source guards, acceptance-map validation, generated inventory refresh, and
  snapshot regeneration completed.
- `git diff --check` completed without findings.
- The capability remains `pending`; no release qualification is claimed.

## Source hashes at receipt close

```text
d95b9bd7bc548ada3c9f154920c2d12a2ae8a360e9927ba52a29795f84841f77  libclamav/pdf.c
9e5de227e4a55bfc4b33c05fac7ac529535a009aa4bc8feefa84a7a6994ccdd0  unit_tests/check_clamav.c
cdc8ef3ac1d2549b8375bb31b5ac3ea460e4ad5627e5f7093d954a93541c0981  tools/largefile_source_guards.sh
566824256a07dbc551cb35b26f9511599eb31ea185e95025ddf60a2d3f9d9803  docs/largefile-capabilities.tsv
66be959d0c9c33cc3a70504e804915ff3de16bf60b462eaac2b4cf09b819f6b9  docs/largefile-capability-case-map.tsv
eba32135ef9d407623ee56ffee6588af69f6677fd824692c62143c0aee5c61ce  docs/largefile-inventory.tsv
ae6659cdf6b9fc822eecc8713f299354fb5a0b85f497a601d55ded5a3dea889b  32gb-current-snapshot.md
```

## Still open

Certified Linux x86-64 evidence, exact/materialized 32-GiB evidence,
production-CVD/service parity, resource and fanotify evidence, independent
format-8 coverage, Sonic1 testing, and final parser/release qualification
remain open under `docs/32gb-luna-execution-roadmap.md`.
