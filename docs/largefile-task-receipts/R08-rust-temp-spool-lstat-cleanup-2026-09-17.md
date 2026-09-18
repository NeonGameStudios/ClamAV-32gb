# R08 Rust temporary-spool pathname inspection hardening — 2026-09-17

Task ID / parent milestone: R08 Rust reader/parser cleanup behavior.

Exact capability kind:id list: shared Rust temporary-spool cleanup behavior;
no capability status was changed.

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`, local HEAD
`6312634ec24539dc6087a76df401a81b8e9aca7c`, intentionally dirty working tree.

Prerequisites verified: the current source tree and generated inventory were
available locally; no package installation, source upload, usage reset,
commit, push, or GitHub workflow action was performed.

Observed failing case and expected behavior: `temp_spool_path_is_owned()`
treated every `lstat()` failure as an identity mismatch. An unexpected
pathname-inspection failure could therefore skip unlinking a retained spool
and still report successful cleanup. The expected behavior is to preserve a
replacement or already-absent path, but return `CL_EUNLINK` for an unexpected
inspection error so cleanup remains fail-visible.

Changes made: Unix pathname inspection now returns a typed result. `ENOENT`
means there is no pathname to remove; a different `lstat()` error becomes a
cleanup failure. Identity mismatches remain non-destructive. Added a regression
for an overlong pathname producing `ENAMETOOLONG`, while retaining the
replacement-file protection test.

Commands, exits, logs and fixture hashes:

* `cargo test --offline --manifest-path libclamav_rust/Cargo.toml
  temp_spool_cleanup_reports_path_inspection_failure --target-dir
  /private/tmp/clamav-rust-target-current` — exit 101 before the test linked;
  the host lacks OpenSSL development discovery (`pkg-config` and OpenSSL
  metadata). No test failure is claimed.
* The same focused test was compiled in the pre-existing `rust:1.97-bookworm`
  container using its direct installed Rust toolchain and the read-only local
  Cargo cache. Compilation reached the test binary, but linking exited 101
  because the standalone crate was not linked with the ClamAV C ABI symbols
  (`cli_versig`, `cli_errmsg`, `cli_checktimelimit`, and related functions).
  No Rust test failure is claimed; the production-linked C/Rust library is
  still required to execute this focused test.
* MCP-SSH documentation was rechecked with `sonic1` / `sonic1-camera-key`:
  `ssh.command.preview(operation=start, timeout_seconds=3600)` was allowed
  with an effective 3600-second limit, and a follow-up `ssh.command.start`
  job completed successfully when polled through `ssh.command.status` and
  `ssh.command.output`. This extends past the short synchronous command
  window, but the available remote ClamAV container remains stale relative to
  the current checkout and was not used as current-source evidence.
* `sh -n tools/largefile_source_guards.sh` — exit 0.
* `sh tools/largefile_inventory.sh` followed by exact comparison against
  `docs/largefile-inventory.tsv` — exit 0.
* `sh tools/largefile_source_guards.sh` — exit 0; all 604 capability bindings
  and included acceptance/evidence checks passed.
* `git diff --check` and snapshot freshness check — exit 0.

Development tests passed: source guards, inventory parity, acceptance/evidence
checks, and static contract verification passed. The linked Rust unit test
remains unexecuted because the local host lacks OpenSSL discovery and the
container attempt lacks the production ClamAV C ABI link context.

Full-size/certified evidence produced, or explicitly not run: none. No
certified Linux x86-64, sanitizer, production-database, full-size, or release
qualification evidence is claimed.

Remaining failures / next slice: run the focused Rust test and current-source
application suite on an authorized runner with the production C/Rust link
context plus complete OpenSSL, JSON-C, and curl development dependencies.
Sonic1 current-source staging and temporary capacity remain open prerequisites.

State: development-verified; runtime-qualification-open
