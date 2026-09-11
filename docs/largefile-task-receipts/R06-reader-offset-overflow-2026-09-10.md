# Task receipt: R06 reader offset-overflow hardening

Task ID / parent milestone: `R06` / `R00`

Exact capability kind:id list: parser:`CL_TYPE_ONENOTE`

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`; existing dirty working tree preserved; the
generated inventory and snapshot were refreshed after this slice.

Prerequisites verified: the reader-backed OneNote parser was audited for
unchecked buffer-growth and cursor-offset additions. No dependency
installation, remote runner, Docker execution, usage reset, commit, push, or
GitHub workflow action was used.

Owned files and excluded shared files: owned the vendored parser reader,
reader regression, source guard, ledger, and receipt metadata. Shared release
labels and qualification records were not promoted.

Observed failing case and expected behavior: stream-buffer growth and cursor
advancement used direct `start + length` arithmetic. If an offset ever reaches
the host limit, the parser must return a resource-visible failure rather than
panic or slice with a wrapped endpoint.

Changes made:

- Added `checked_reader_end()` and used it for refill resize/truncate and
  stream cursor slicing.
- Added a focused `usize` overflow regression asserting the resource-visible
  error classification.

Commands, exits, logs and fixture/database hashes:

- `git diff --check` and source-control checks are run after the source change.
- The full parser package test profile remains unavailable because the offline
  Cargo cache lacks `insta`; no toolchain component or dependency was
  installed.
- A standalone `rustc --test` harness over the current `reader.rs` passed all
  9 reader tests, including `reader_offset_addition_overflow_is_resource_visible`.
- Inventory, snapshot freshness, and the full source/evidence guard sweep are
  recorded after this slice.

Development tests passed: the standalone current-source reader harness passed
9/9; the linked parser package cannot be built on this host because of the
uncached offline test dependency.

Full-size/certified evidence produced, or explicitly not run: not run. No
current-source C/Rust consumer build, materialized late-content fixture,
Linux x86-64 Release/sanitizer build, or R04 qualification record exists for
this slice.

Remaining failures / next slice: the parser’s upstream attachment model still
materializes embedded-file payloads; a reader-backed streaming extraction API
or reviewed dependency fork is still required before R06 can close. Certified
runner and full-size qualification remain open.

State: development-verified
