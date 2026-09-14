# Task receipt: R09 fuzzy-image null-context status

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `matcher:rust-fuzzy-image-ffi-admission`;
the related `matcher:fuzzy-image` row remains linked and unpromoted.

Scope: preserve the public FFI distinction between a missing scan context and
malformed or unreadable encoded image data.

Observed gap:

- `fuzzy_hash_calculate_image_fmap()` rejected a null scan context through the
  reader helper, but `fuzzy_hash_reader_status()` mapped the resulting
  `Error::NullParam` to generic `CL_EPARSE`.

Changes:

- `Error::NullParam(_)` now maps to `CL_ENULLARG` in the reader-backed status
  conversion.
- A focused unit regression asserts the exact status for the `scan_ctx`
  argument boundary.
- The source guard pins both the status branch and regression.

Verification:

- `git diff --check` and the full source-guard sweep must be rerun after this
  slice.
- Full local Cargo remains unavailable because the offline cache lacks the
  `insta` dev dependency; no software was installed.
- The updated private source was not exported to Sonic1 after MCP-SSH
  rejected that destination; no workaround or remote runtime claim is made.

No capability was promoted. Full crate, linked current-source execution,
sanitizer, certified, full-size, production-service, R04-record, and final
release qualification remain open.

State: `implemented`; focused compile/runtime verification remains pending.
