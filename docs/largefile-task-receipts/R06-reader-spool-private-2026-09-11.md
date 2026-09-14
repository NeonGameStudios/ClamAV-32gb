# Task receipt: R06 private OneNote reader spool hardening

Task ID / parent milestone: `R06` / `R00`.

Scope: keep stream-backed OneNote object-data spools private and prove that a
short source cannot leave a partial parser spool behind.

Changes:

- `ReaderSpool` creates object-data temporary files with owner-only `0600`
  permissions on Unix hosts. These blobs can contain user documents and must
  not inherit a permissive process umask.
- The reader unit profile now covers partial-spool cleanup after a declared
  blob is truncated and checks the Unix permission mode of a live spool.
- The focused source guard binds both regressions and the private-file mode.

Verification:

- `git diff --check` passed.
- `sh -n tools/largefile_source_guards.sh` passed.
- The full `sh tools/largefile_source_guards.sh` sweep passed after refreshing
  `docs/largefile-inventory.tsv` (597 capability entries and all evidence/schema
  controls).
- A minimal temporary `rustc --test` harness for the edited `reader.rs`
  compiled and ran all 12 reader tests successfully, including both new spool
  regressions. This is module-level evidence, not a full crate build.
- Local `cargo test --offline --all-targets` could not resolve the uncached
  `insta` dev dependency (`cargo` exit 101); no software was installed.
- The updated source was not uploaded to Sonic1 because MCP-SSH rejected that
  export as an unauthorized private-source destination. No workaround or
  remote claim is made for this specific change.

No capability was promoted. Current-source linked execution, sanitizer,
certified Linux x86-64, full-size, production-service, R04-record, and final
release qualification remain open.

State: `implemented`; linked runtime verification remains pending.
