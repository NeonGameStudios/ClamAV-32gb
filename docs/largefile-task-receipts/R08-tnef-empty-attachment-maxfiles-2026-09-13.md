# Task receipt: R08 TNEF empty-attachment MaxFiles accounting — 2026-09-13

State: `development-verified`; no capability promoted.

## Gap

The TNEF parser treated every zero-length attribute as metadata and skipped
attachment-level `attAttachData` before child admission. The TNEF grammar
allows zero-byte attribute data, so a valid empty by-value attachment could
bypass the inclusive `MaxFiles` budget. Zero-length message metadata is not a
logical child and remains unchanged.

## Change

- Added `tnef_admit_empty_attachment()` and call it for zero-length
  attachment-level `attAttachData` before consuming its checksum.
- Added `test_tnef_empty_attachment_counts_toward_maxfiles`, covering
  `MaxFiles=1` rejection with the canonical
  `Heuristics.Limits.Exceeded.MaxFiles` reason and cache taint, plus exact
  `MaxFiles=2` completion with `scannedfiles` incremented to 2.
- Registered source guards and updated the TNEF capability description.

The format reference is Microsoft’s [MS-OXTNEF ABNF description](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxtnef/b03b5704-ef54-4390-b981-dc78f8e79a05), which defines attribute `Data` as zero or more octets.

## Verification

- Release `cmake --build /tmp/clamav-release-current-20260913 --target check_clamav -j2`: exit 0.
- Release focused `CK_RUN_SUITE=cl_suite CK_RUN_CASE=tnef T=1200 ctest --output-on-failure -R '^libclamav$'`: exit 0, 19/19.
- ASan/UBSan `cmake --build /tmp/clamav-asan-current-20260912 --target check_clamav -j2`: exit 0.
- ASan/UBSan focused `ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 CK_RUN_SUITE=cl_suite CK_RUN_CASE=tnef T=1200 ctest --output-on-failure -R '^libclamav$'`: exit 0, 19/19, no sanitizer diagnostics.
- `sh tools/largefile_source_guards.sh`: exit 0.
- `diff -u docs/largefile-inventory.tsv <(sh tools/largefile_inventory.sh)`: exit 0.
- `git diff --check`: exit 0.

Source hashes at receipt close:

- `libclamav/tnef.c`: `f0fb793fec5b62f116646759e88f33ac39a7d32a8ff0404cbf3fdb55bb8db3a0`
- `unit_tests/check_clamav.c`: `aa0f96971cf0773408e80bdd7d5b2219feb86543d15ccf7b3ec4365e9e54c0a4`
- `tools/largefile_source_guards.sh`: `1ab01529537acf2edb9d5ce3f69598ec837b76d52a5da31191e384c3509b8464`
- `docs/largefile-capabilities.tsv`: `8bdaf1235705b2fba44574c77ee980ab0f75d67844038b47509015a0fceb98ef`
- `docs/largefile-inventory.tsv`: `ea4e9be139219d130af91e1b9cf19aa42e1c4adb1f6d817a5b89f542f219a815`

## Limitations and next action

This is ARM64 Docker development evidence only. Certified Linux x86-64,
complete TNEF corpus, exact/materialized 32-GiB, production CVD/service,
resource/fanotify, Sonic1, independent format-8, and final release evidence
remain open. These development checks do not qualify the capability for
release.
