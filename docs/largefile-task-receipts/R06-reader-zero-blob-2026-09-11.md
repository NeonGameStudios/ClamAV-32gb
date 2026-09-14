# Task receipt: R06 zero-length OneNote reader blob

Task ID / parent milestone: `R06` / `R00`.

Scope: remove an unnecessary temporary-file side effect for empty streamed
OneNote object-data blobs while retaining disk-backed storage for non-empty
payloads.

Changes:

- `Reader::read_blob(0)` now returns an empty in-memory blob without creating
  a parser spool. Non-empty stream-backed blobs retain the bounded refill and
  private-spool path.
- The reader unit profile now asserts the zero-length representation under
  the existing serialized spool test lock.
- The source guard pins the zero-length branch and regression.

Verification:

- `git diff --check` passed before this slice and must be rerun after it.
- `sh -n tools/largefile_source_guards.sh` passed before this slice and must
  be rerun after it.
- The temporary `rustc --test` reader harness must be rerun after this edit;
  full local Cargo remains unavailable because the offline cache lacks the
  `insta` dev dependency.
- The updated source was not exported to Sonic1 after MCP-SSH rejected that
  private-source transfer as an unauthorized destination. No workaround or
  remote claim is made for this change.

No capability was promoted. Full crate, linked runtime, sanitizer, certified,
full-size, production-service, R04-record, and final release qualification
remain open.

State: `implemented`; linked runtime verification remains pending.
