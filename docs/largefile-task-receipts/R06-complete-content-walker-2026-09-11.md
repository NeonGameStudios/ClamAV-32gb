# Task receipt: R06 OneNote complete content walker

Task ID / parent milestone: `R06` / `R00`

Scope: make scanner-facing and compatibility OneNote extraction visit every
parsed attachment-bearing content location in a page: the page title,
page-level content, outline groups/elements/children, and table-cell outline
elements. This is a bounded functional correction; it does not promote
OneNote or release readiness.

Starting state: branch `largefile-roadmap-qualification`, current working
tree based on HEAD `8e837b88`; existing privacy, roadmap, parser, tooling,
and receipt changes were preserved. Shared acceptance/snapshot files were not
reinterpreted as qualification evidence.

## Observed gap and correction

The parser materializes page titles as outlines and table content as nested
outline elements. The extraction path did not walk either structure: it
handled page contents and outline content, but treated table content as a
leaf and skipped `Page::title()` entirely. Attachments in those valid parsed
locations could therefore be omitted from both scanner callbacks and the
compatibility iterator.

The shared walker now:

- walks every outline in a page title;
- handles `OutlineItem::Group` and `OutlineElement::children()` recursively;
- descends through table rows, cells, and their outline elements; and
- preserves callback-driven early termination through all nested paths.

The compatibility iterator continues to reuse this same walker, so the
scanner and iterator have one extraction boundary.

## Verification

- `cargo test --offline --manifest-path /private/tmp/clamav-32gb-onenote-module/Cargo.toml --lib` — **21 passed** against the current source.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `python3 -B tools/largefile_service_workload_check_test.py` — **28 passed; 2 expected Linux-only skips**.
- Acceptance map and zero-record schema checks — **passed; 597 capabilities**.
- Snapshot freshness, refreshed inventory, shell syntax, targeted title/group/
  child/table guards, and `git diff --check` — **passed**.
- The bundled sample contains no embedded-file fixture; no fixture-based
  title, child, group, or table attachment count is claimed.

No capability was promoted. Certified Linux x86-64, sanitizer, full-size
materialized, production-service, R03-runner, R04-record, and final release
qualification remain open. The full consumer Cargo check remains blocked by
the pre-existing offline `clam-sigutil` tag reference; no dependency or
toolchain was installed or downloaded. No remote execution, usage reset,
GitHub workflow action, commit, or push was used.

State: implementation slice development-verified; release qualification
remains blocked.
