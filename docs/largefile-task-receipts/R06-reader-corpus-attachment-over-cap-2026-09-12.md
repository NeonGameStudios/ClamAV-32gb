# Task receipt: R06 OneNote corpus attachment over-cap reader — 2026-09-12

Task ID / parent milestone: `R06` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. Final current-source manifest SHA-256 after this
slice's source and guard changes:
`9d682db828b0ba68d7ab8a92956e9b11c44dfe2c9879c6b2af9f4399e27af644`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used.

Observed gap and expected behavior: the existing reader-over-cap test proved
that a valid modern OneNote section can finish past the former 256 MiB
whole-input boundary, but it did not prove that an embedded child is handed
off through the same path. A valid attachment-bearing section must be
detected when the logical fmap length is above that boundary, without
materializing the padded tail.

Changes and evidence:

- Added `test_rust_onenote_reader_streams_corpus_attachment_above_former_cap`
  to `unit_tests/check_clamav.c`. It uses the real decrypted
  `clam.exe.2010.one` attachment-bearing corpus, serves it through the
  bounded `cl_fmap_open_handle()` callback, and advertises a logical length
  of `256 * 1024U * 1024U + 1U`.
- The test uses the production `scan_onenote()` entrypoint, a two-layer scan
  stack for the extracted child, and an isolated `OneNote.Reader.MZ` content
  signature. A positive result therefore demonstrates reader-backed
  attachment extraction and nested child scanning rather than raw matching
  the container.
- The source guard pins the test and its `tc_rust_onenote` registration.
- Reader-backed parser object-data blobs now reserve their written extents
  through the shared scan temporary-byte budget, release those reservations
  when the parser-owned spool drops, and use the current layer's temporary
  directory. The parser unit controls cover successful reservation/release
  and refusal before an over-budget extent is written.

Verification performed:

- Refreshed ARM64 Docker `RelWithDebInfo` build completed at 100% after the
  test addition.
- Focused linked `cl_suite/rust_onenote` passed 4/4 checks, including the
  existing over-cap clean parse and the new over-cap attachment detection.
- The isolated current-source OneNote parser suite passed 77/77 tests,
  including the new shared temporary-budget controls.
- The core normal application matrix passed 5/5:
  `libclamav_rust`, `clamscan`, `clamd`, `freshclam`, and `sigtool`.
- The complete correctly configured normal `libclamav` CTest target passed
  2865 checks with 0 failures and 0 errors using host-backed temporary
  storage. During that run, a real partial-message spool defect was fixed by
  giving its private directory owner execute permission, and the long-path
  CVD regression was made portable across bind-mounted runners with a long
  logical symlink chain.
- An earlier unfiltered normal `libclamav` attempt was stopped by the
  disposable Docker filesystem reaching zero allocatable space while
  writing its own large temporary fixtures; its failures were short writes
  and temporary-spool writes, not this OneNote case. The focused test was
  rerun with its disposable temp directory on the host-backed source mount
  and passed.
- Source manifest generation, the regenerated inventory comparison, the full
  repository source guards, and `git diff --check` passed.

Qualification boundary: this is current-source ARM64 Docker development
evidence, not the roadmap's certified Linux x86-64 Release profile. It proves
reader-backed attachment extraction above the former whole-input boundary;
it does not prove all OneNote late-offset variants, full-size materialized
corpus behavior, sanitizer cleanliness for this new case, production-CVD or
service behavior, Sonic1 execution, or final release qualification. No
capability was promoted.

Current release gate remains blocked: 597 total, 0 qualified, 143 bounded,
440 pending, 14 allowlisted unsupported, and 583 blockers.

State: `development-verified`; linked current-source reader-over-cap corpus
attachment test passed; certified R06 completion remains pending.
