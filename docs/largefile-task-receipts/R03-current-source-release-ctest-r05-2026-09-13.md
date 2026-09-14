# Task receipt: R03 current-source Release CTest after R05

Task ID / parent milestones: `R03` / `R05`, `R10`, `R11`

The existing ARM64 Docker Release tree was reconfigured and rebuilt against
the current mounted repository after the R05 streaming/ZIP64 fixture change.
Its 1,697-entry source manifest is bound to SHA-256
`7c9e98e508dea7060cf515f952d734b311bd5be2bfeb3816b1cbcfb7a0eebf00`.

Command:

```text
docker exec clamav-current-rust-build-20260911 \
  ctest --test-dir /tmp/clamav-release-current-20260913 --output-on-failure
```

Result: `100% tests passed, 0 tests failed out of 28`; total elapsed time was
189.04 seconds. The matrix included the complete `libclamav` target, all
large-file admission/evidence/source-guard controls, the registered ZIP
late-member suite, Rust integration, `clamscan`, `clamd`, `freshclam`,
`sigtool`, clamdscan controls, and both milter targets.

This is current-source ARM64 Docker development verification. It does not
qualify exact 32-GiB/materialized fixtures, certified Linux x86-64 resources,
production-CVD/service behavior, privileged fanotify, Sonic1, independent
format-8 execution, or final release readiness. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
