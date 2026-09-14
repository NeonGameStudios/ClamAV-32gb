# Task receipt: R03 current application smoke — 2026-09-13

Task ID / parent milestone: `R03` / `R10`.

## Scope

Rebuild the current-source application targets in the preserved Docker
toolchain and exercise the `clamscan` executable against one clean and one
known test input. This is a local ARM64 development smoke check; it is not a
release or Sonic1 qualification run.

## Evidence

Runner: existing `clamav-current-rust-build-20260911` container, image
`rust:1.97-bookworm`, source mounted at `/src`.

The command

```text
docker exec clamav-current-rust-build-20260911 sh -lc \
  'cmake --build /tmp/clamav-asan-current-20260912 --parallel 2'
```

completed with exit `0`. The coherent current-source ASan/UBSan build reached
100% and rebuilt `clamscan`, `clamd`, `clamdscan`, `clamonacc`,
`clamav-milter`, `sigtool`, `clambc`, and the registered Check/pool targets.

Using the build's certificate directory and the deterministic test HDB:

```text
clamscan --cvdcertsdir=/tmp/clamav-asan-current-20260912/certs \
  --database=/tmp/clamav-asan-current-20260912/unit_tests/input/clamav.hdb \
  --no-summary <clean fixture>
```

returned exit `0` and `OK`. The same invocation against the generated
`clam.zip` fixture returned exit `1` with the expected
`ClamAV-Test-File.UNOFFICIAL FOUND` result. No sanitizer diagnostic was
emitted by either executable run.

The current source manifest remains 1,697 entries with SHA-256
`5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`, and
`git diff --check` passes.

## Qualification boundary

This proves the application binary can rebuild and perform basic clean and
detection scans on the development runner. It does not replace certified
Linux x86-64, exact 32-GiB/materialized edges, production CVD/service,
privileged fanotify, independent format-8 bytecode, Sonic1, or final release
evidence. Readiness remains `blocked`.

No software was installed, no usage reset was used, and no GitHub workflow,
commit, or push was performed.

State: `development-smoke-verified; qualification-blocked-by-runner-and-fixtures`.
