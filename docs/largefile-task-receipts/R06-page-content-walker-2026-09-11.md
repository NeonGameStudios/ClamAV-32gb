# Task receipt: R06 OneNote page-content extraction walker

Task ID / parent milestone: `R06` / `R00`

Scope: make scanner-facing and compatibility OneNote extraction visit
embedded files represented directly as page contents, and keep both APIs on
one traversal implementation. This is a bounded functional correction; it
does not promote OneNote or release readiness.

## Correction

`scan_section()` previously inspected embedded files only below outline
elements. The parser's public `PageContent` model also admits an
`EmbeddedFile` directly at page level, so such a valid attachment was parsed
but never handed to the scanner or returned by `OneNote::from_bytes()`.

The common walker now checks each page content for a direct embedded file
before descending into outlines. The compatibility iterator's modern parser
path now reuses that walker instead of maintaining a second, outline-only
implementation.

## Verification

- `cargo test --offline --manifest-path /private/tmp/clamav-32gb-onenote-module/Cargo.toml --lib` — **21 passed** against the current source.
- The current parser-source sample harness parsed `New Section 1.one`; the
  sample contains **0 direct and 0 nested embedded files**, so no fixture-based
  attachment count is claimed for this correction.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `python3 -B tools/largefile_service_workload_check_test.py` — **28 passed; 2 expected Linux-only skips**.
- Acceptance map and zero-record schema checks — **passed; 597 capabilities**.
- Snapshot freshness, inventory refresh, shell syntax, targeted walker guards,
  and `git diff --check` — **passed**.
- Full `libclamav_rust` consumer checking remains blocked before compilation:
  offline Cargo cannot resolve the pre-existing `clam-sigutil` tag reference.
  No dependency or toolchain was installed or downloaded.

No capability was promoted. Certified Linux x86-64, sanitizer, full-size
materialized, production-service, R03-runner, R04-record, and final release
qualification remain open. No remote execution, usage reset, GitHub workflow
action, commit, or push was used.

State: implementation slice development-verified; release qualification
remains blocked.

