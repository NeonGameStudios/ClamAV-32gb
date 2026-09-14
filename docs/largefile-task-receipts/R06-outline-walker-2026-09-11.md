# Task receipt: R06 OneNote recursive outline walker

Task ID / parent milestone: `R06` / `R00`

Scope: make scanner-facing and compatibility OneNote extraction follow the
parser's complete outline tree, including grouped outlines and child outline
elements. This is a bounded functional correction; it does not promote
OneNote or release readiness.

## Correction

The parser represents outline groups and nested outline-element children
recursively, but the extraction code previously inspected only the first
element exposed by each top-level outline item. Valid embedded files below a
group or child element could therefore be parsed and then omitted from both
the scanner callback and the compatibility iterator.

The shared walker now recursively handles `OutlineItem::Group`, scans each
element's contents, and descends through `element.children()`. A callback
request to stop propagates through every recursion level, preserving the
existing early-termination behavior.

## Verification

- `cargo test --offline --manifest-path /private/tmp/clamav-32gb-onenote-module/Cargo.toml --lib` — **21 passed** against the current source.
- Host tooling from the immediately preceding OneNote walker slice passed
  **147 tests with 2 expected skips**; service workload checks passed **28
  tests with 2 expected Linux-only skips**.
- Acceptance map and zero-record schema checks — **passed; 597 capabilities**.
- Snapshot freshness, inventory refresh, shell syntax, targeted recursive
  walker guards, and `git diff --check` — **passed**.
- The bundled sample contains no embedded-file fixture, so no fixture-based
  nested-attachment count is claimed.

No capability was promoted. Certified Linux x86-64, sanitizer, full-size
materialized, production-service, R03-runner, R04-record, and final release
qualification remain open. No dependency or toolchain was installed or
downloaded; no remote execution, usage reset, GitHub workflow action, commit,
or push was used.

State: implementation slice development-verified; release qualification
remains blocked.
