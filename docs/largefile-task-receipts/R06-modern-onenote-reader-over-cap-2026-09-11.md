# Task receipt: R06 modern OneNote reader-over-cap admission — 2026-09-11

Task ID / parent milestone: `R06` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, starting commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the existing intentionally
dirty working tree preserved. The final source-manifest SHA-256 is recorded
after the capability bookkeeping and inventory refresh below:
`ff38e2ab5e7d9d7a59da77ff757a4984f35313f6a57cbafd1e7e5693b1f526f0`.
No host
dependency installation, usage reset, commit, push, or GitHub workflow action
was used.

Observed gap and expected behavior: the modern OneNote parser previously
materialized the complete input and enforced a 256 MiB whole-input boundary.
The production scanner now uses the bounded reader-backed path. A valid modern
section must therefore be able to complete when its logical fmap length is
256 MiB plus one byte, without reading or materializing the zero-filled tail.

Changes and evidence:

- The test `test_rust_onenote_reader_crosses_former_whole_input_cap` reads the
  repository's valid modern `New Section 1.one` sample, presents it through a
  bounded `cl_fmap_open_handle()` callback, and gives the production
  `scan_onenote()` entrypoint a logical length of
  `256 * 1024U * 1024U + 1U`. The callback only serves the sample bytes and
  zero-fills reads beyond them; no 256 MiB input buffer is allocated.
- The test invokes the same current-source Rust reader-backed scanner used by
  the application, and asserts clean completion with no sticky incomplete or
  non-cacheable state.
- The source guard pins the test, logical-length boundary, and
  `tc_rust_onenote` registration. The capability description and generated
  inventory were updated to bind this evidence.

Verification performed:

- Current-source incremental CMake build completed at 100% in the disposable
  ARM64 container with `RelWithDebInfo`, tests enabled, static libraries
  enabled, shared libraries disabled, and large-file defaults and the
  qualification test disabled.
- Linked `cl_suite/rust_onenote`: 3 checks, 0 failures, 0 errors.
- After regenerating the inventory, the updated CTest integration/control
  selection passed 11/11, including `libclamav`, `clamscan`, `sigtool`, source
  guards, runtime evidence, acceptance capture, clamscan admission, daemon
  report protocol, ZIP late member, and milter quota checks.
- The complete current CTest matrix passed 15/15, adding the sparse probe,
  Rust package, `clamd`, and `freshclam` targets.
- The host source guard, snapshot consistency, shell syntax, inventory
  consistency, and `git diff --check` checks passed.

Qualification boundary: this is current-source ARM64 Docker development
evidence, not the roadmap's certified Linux x86-64 profile. It proves the
reader-backed scanner crosses the former whole-input boundary; it does not
prove fully materialized input compatibility, late-child detection at an
independently expected offset, full-size model/file corpus behavior, sanitizer
cleanliness, production-CVD/service behavior, Sonic1 execution, or final
release qualification. No capability was promoted.

Current release gate remains blocked: 597 total, 0 qualified, 143 bounded,
440 pending, 14 allowlisted unsupported, and 583 blockers.

State: `implemented`; linked current-source reader-over-cap development
verification passed; certified R06 completion remains pending.
