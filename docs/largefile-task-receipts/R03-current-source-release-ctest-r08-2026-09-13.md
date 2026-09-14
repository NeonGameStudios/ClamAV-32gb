# R03 current-source Release CTest revalidation — 2026-09-13

Task ID / parent milestone: `R03` / `R01`.

After the provenance rebind, the existing ARM64 Docker Release tree was
rebuilt and its complete application/test matrix was rerun. The current
source manifest is SHA-256
`12aecbdf0c16bfae5aabb5480bb89554f6fcbd9e3ab77f6d2180ba43680e1f42`; the
Release CMake cache is
`d2c8b698107393f57d109a486b1a50d2d830a4f482b8393d97f216b58b646869`.

Command:

```text
docker exec clamav-current-rust-build-20260911 sh -c \
  'cd /tmp/clamav-release-current-20260913 && ctest --output-on-failure'
```

Result: exit 0; **28/28 tests passed** in 194.94 seconds. Coverage included
the complete `libclamav` group, source/readiness/evidence controls, acceptance
schemas and resource capture, development acceptance capture, clamscan,
clamd, clamdscan, Rust, milter, freshclam, sigtool, and the large-file
controls. No test failures or sanitizer diagnostics occurred.

This is ARM64 Docker development evidence only. Certified Linux x86-64,
exact/materialized 32-GiB resources, production CVD/Sonic1, privileged
fanotify, independent bytecode format-8, and final release qualification
remain open. No capability was promoted.

No usage reset, installation, commit, push, workflow action, or remote
mutation was performed.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`.
