# Task receipt: R06 reference-stream short-input handling

Task ID / parent milestone: `R06` / `R00`

Scope: make OneNote embedded-ink and note-tag reference adapters fail closed
when a declared reference range is longer than the corresponding object or
object-space stream. This is a bounded implementation slice; it does not
promote OneNote or release readiness.

## Correction

`embedded_ink_container` and `note_tag_container` now validate the complete
offset/count range before copying compact IDs. Previously, `saturating_sub()`
and `min()` silently shortened a malformed declaration to the available
stream, allowing an incomplete child object to continue as if its references
were complete. The shared object and object-space range validators are now
crate-visible to these adapters. A current-source regression proves that a
short object-space stream is rejected.

## Verification

- `cargo test --offline --manifest-path /private/tmp/onenote-parser-check/Cargo.toml --lib` — **62 passed**.
- `cargo test --offline --manifest-path /private/tmp/onenote-host-check/Cargo.toml` — **21 passed**.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `python3 -B tools/largefile_service_workload_check_test.py` — **28 passed; 2 expected Linux-only skips**.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — **597 capabilities passed**.
- `python3 -B tools/largefile_acceptance_cases.py --check-records` — **0-record schema passed**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- `git diff --check` — **passed**.
- Targeted source assertions confirm the new short-stream regression and the
  removal of both silent truncation expressions.

The current-source manifest generated after this slice is bound by SHA-256
`de8dbaeb367b6c8b9034f2febc31da222db83fbfc4f55426c46a9e6f836ba853`.
The generated line inventory was refreshed. Certified Linux x86-64,
sanitizer, materialized late-content, production service, R03 runner, R04
records, and final release qualification remain open. No capability was
promoted. No remote execution, MCP-SSH, usage reset, GitHub workflow action,
commit, or push was used.

State: implementation slice development-verified; release qualification
remains blocked.
