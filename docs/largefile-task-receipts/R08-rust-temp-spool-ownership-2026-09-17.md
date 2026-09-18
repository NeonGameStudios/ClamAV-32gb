# R08 Rust temporary-spool ownership hardening — 2026-09-17

## Scope

Harden the shared Rust `TempSpool` used by the ALZ, LHA/LZH, and OneNote
scanner paths. The spool now captures the Unix device/inode of the descriptor
returned by temporary-file creation, and cleanup checks that the pathname
still identifies that same object before unlinking it. If descriptor identity
cannot be captured, construction fails closed and releases the reservation.

This closes the stable replacement-path cleanup exposure for the shared Rust
spool. The check is a fail-closed ownership recheck; it does not claim a
kernel-atomic unlink guarantee against a replacement occurring after the
identity check.

## Verification

- `sh tools/largefile_inventory.sh` output matches
  `docs/largefile-inventory.tsv`.
- `git diff --check`: passed.
- `sh tools/largefile_source_guards.sh`: exit 0; the repository source,
  manifest, acceptance-contract, fixture, and evidence guards passed.
- Added a Unix regression covering replacement of the spool pathname with an
  unrelated regular file; the regression is compile/test source coverage but
  was not executed because the top-level Rust crate cannot currently compile
  in this environment.

The top-level `clamav_rust` integration compile remains blocked by the
macOS worktree's missing discoverable OpenSSL development files and
`pkg-config`; the existing offline Rust container is additionally missing the
pinned `clam-sigutil` Git dependency from its Cargo cache. No dependency or
Rust component was installed.

This is development verification only. It does not qualify full-size,
materialized, certified Linux x86-64, sanitizer, or release evidence.

State: `development-verified; integration-and-qualification-open`
