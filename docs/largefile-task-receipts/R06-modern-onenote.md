# Task receipt: R06 modern OneNote parser boundary audit

Task ID / parent milestone: `R06` / `R00`

Scope: determine whether the pinned modern OneNote dependency provides a
reader/seek-backed parsing boundary suitable for inputs beyond the current
256 MiB whole-input cap. This receipt records an audit only; it does not
promote OneNote or change the fail-visible cap.

Prerequisites verified:

- The canonical checkout and dirty working tree were preserved.
- `libclamav_rust/src/scanners.rs` refuses modern OneNote inputs above
  `FMap::WHOLE_INPUT_MAX` and returns `CL_ERESOURCE`.
- `libclamav_rust/src/onenote.rs` calls the pinned dependency's
  `Parser::parse_section_buffer(&[u8], &Path)` API for modern sections.
- The cached dependency checkout also exposes `Parser::parse_section(&Path)`,
  but its implementation calls `read_to_end` into a `Vec<u8>` before parsing;
  it is therefore not a streaming substitute.

Observed blocker and expected behavior:

- The pinned `onenote_parser` source has no public reader/seek-backed section
  API. Its internal `Reader` is a wrapper around `&[u8]`, and the path API
  materializes the entire file. Raising `WHOLE_INPUT_MAX`, mapping a larger
  file, or switching to `parse_section` would violate the roadmap's bounded
  reader/spool requirement.
- An offline test of the cached dependency could not run because the local
  Cargo cache lacks the `insta` crate (`cargo test --offline` exit 101).
  No dependency was downloaded or installed.

Conclusion: no safe in-repository OneNote implementation change was made in
this slice. Closing R06 requires either a reviewed reader-backed upstream API
or a substantial bounded parser implementation/fork that preserves the
dependency's format semantics, plus a current-source build and valid modern
fixture. The existing legacy reader-backed path and modern fail-visible
refusal remain intact.

State: `blocked-by-dependency-api`; release readiness remains blocked.
