# Task receipt: R06 notebook TOC path and recursion hardening

Task ID / parent milestone: `R06` / `R00`

Scope: keep filesystem-backed OneNote notebook traversal within the notebook
directory and bound nested TOC/group recursion without changing section-parser
format handling.

Changes made:

- Reject empty, absolute, parent-containing, and special-component TOC paths
  before joining them to the notebook directory.
- Use `symlink_metadata` for TOC entries and skip symlinked nested TOC files so
  external filesystem targets are not followed.
- Bound nested notebook/group traversal with the shared OneNote recursion
  budget.
- Add focused path-resolution regressions for safe relative and rejected TOC
  names.

Commands and results:

- `cargo test --offline` in `/private/tmp/clamav-32gb-onenote-module` — exit 0;
  current-source harness compiled and passed 18 tests.
- `cargo test --offline --lib` in `libclamav_rust/onenote_parser` — blocked
  before test compilation because the offline cache lacks `insta`.
- `cargo fmt --check` — unavailable because `cargo-fmt` is not installed; no
  toolchain component was installed.
- `sh tools/largefile_inventory.sh` — exit 0; refreshed 597-capability
  inventory.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — exit 0.
- `git diff --check` — exit 0.
- `sh tools/largefile_source_guards.sh` — exit 0; all source, schema,
  producer, service, protocol, boundary, and acceptance-map guards passed.

Limitations:

- No coherent current-source C build, certified runner, full-size materialized
  evidence, Docker/remote SSH execution, or R04 qualification record is claimed.

State: `development-verified`; release readiness remains blocked.
