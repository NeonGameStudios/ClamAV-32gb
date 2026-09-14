# R08 HFS+ ExtentOverflow resolution receipt — 2026-09-12

## Scope

Implement the HFS+ fork path required when a fork exhausts its eight inline
extent descriptors. The implementation must resolve the fork's
`ExtentOverflow` B-tree records without weakening HFS+ fail-closed behavior.

## Implementation

- `hfsplus_scanfile()` now walks logical fork blocks through a checked resolver
  rather than assuming the inline descriptor list is complete.
- ExtentOverflow records are matched by fork type, catalog file ID, and logical
  starting block. Leaf-node offsets, key sizes, descriptor ranges, volume
  coordinates, record counts, forward links, cycles, and the shared scan
  deadline are validated before a physical block is read.
- The ExtentOverflow file itself is constrained to its inline fork; recursive
  overflow and missing or unrepresentable records fail visibly and remain
  non-cacheable.
- The regression fixture maps both a catalog leaf chain and a nine-block data
  fork through ExtentOverflow and reaches an exact child signature in the
  overflow-only block.

## Verification

- Focused production-linked `hfs_fork`: `2/2`, zero failures and errors.
- Current-source ARM64 Release `check_clamav`, `clamd`, and `clamscan` targets
  rebuilt successfully in the existing `rust:1.97-bookworm` container.
- Complete current-source ARM64 Release CTest matrix: `28/28` passed in
  `165.40` seconds, including LibClamAV, clamscan, clamd, freshclam, sigtool,
  milter, Rust, source guards, acceptance/resource contracts, and service
  evidence checks.
- Source guards passed all 601 capability rows; the tracked inventory and
  status snapshot were regenerated and freshness checks passed.
- `git diff --check` passed.

## Qualification state

This is development verification only. HFS+ remains pending complete
catalog/attribute/resource/ExtentOverflow corpus coverage, certified Linux
x86-64, production-CVD/service parity, materialized large-file/resource tests,
Sonic1 evidence, and final parser/release qualification. Focused sanitizer
evidence is now recorded below; it does not replace the full qualification
profile.

The implementation-slice source manifest contained 1,697 entries and hashed
to
`436caac47eb38f1de6470bba94e1ca61ba30b80cf3f7cf018eb897caf46300ce`.

## Sanitizer follow-up — 2026-09-12

The existing disposable `rust:1.97-bookworm` ARM64 container was used with a
fresh current-source C ASan/UBSan build. No host software was installed, and
the CVD fixture tests used the repository's existing test certificate
directory.

- `rust_onenote`: `4/4`, zero failures/errors with leak detection enabled.
- `hfs_fork`: `2/2`, zero failures/errors with leak detection enabled.
- `bytecode`: `88/88`, zero failures/errors with leak detection enabled.
- The HFS+ regression fixture now closes its first mapped scan before
  replacing it, eliminating the sanitizer-reported 312-byte fixture leak.
- Source guards, capability/snapshot validation, and `git diff --check` pass
  after regenerating the derived inventory.

This remains focused ARM64 development evidence. It is not the roadmap's
certified Linux x86-64 sanitizer run, nightly Rust sanitizer profile,
materialized 32-GiB workload, production-CVD/service proof, Sonic1 evidence,
or final release qualification.
