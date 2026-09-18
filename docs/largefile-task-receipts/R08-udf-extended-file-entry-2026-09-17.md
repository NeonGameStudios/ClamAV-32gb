# R08 — UDF Extended File Entry admission

Date: 2026-09-17
Roadmap: `docs/32gb-luna-execution-roadmap.md`, R08
Scope: bounded Extended File Entry (EFE, descriptor tag 266) support in the
anchored UDF tree path.

## Change

The anchored and legacy linear UDF paths now accept both regular File Entry
and Extended File Entry descriptors. EFE fixed-header, extended-attribute,
and allocation-descriptor lengths use checked native-width addition before
descriptor-tag validation or field consumption. The common directory/file-
type, logical information-length, allocation-window, and nested-scan path is
reused for EFE children.

The standards-shaped UDF fixture now scans a valid EFE child through the
existing `Udf.File.Marker.UNOFFICIAL` nested marker path. It also rejects an
EFE whose fixed header plus declared extended-attribute area exceeds its
logical block, preserving sticky incomplete state and cache taint. The size
oracle covers normal EFE variable-area arithmetic alongside the existing FE
oracle.

The implementation remains bounded to the existing supported allocation
descriptor forms and 2,048-byte logical-block contract; complete UDF EFE
coverage and qualification remain open.

## Evidence

- The full repository source-guard suite passed after the EFE fixture,
  documentation, and generated-artifact updates: 604 capability entries,
  readiness checks, inventory parity, acceptance-map/record checks, and
  source guards.
- `git diff --check` passed and the generated snapshot freshness check passed.
- The linked UDF unit and sanitizer runners remain unexecuted: the local
  container became unavailable and the available toolchain lacks the required
  JSON-C/Check/OpenSSL development prerequisites. Sonic1 also timed out during
  two read-only Docker probes at SSH connect (`remote_started=false`), so no
  remote qualification claim is made.

State: implemented; focused-target-registered; qualification-pending.
