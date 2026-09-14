# Task receipt: R03 current-source ASan/UBSan CTest after R05

Task ID / parent milestones: `R03` / `R05`, `R10`, `R11`

The existing ARM64 ASan/UBSan tree was reconfigured and rebuilt against the
current mounted repository after the R05 streaming/ZIP64 fixture change. The
current 1,697-entry source manifest is
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f` and the
reconfigured CMake cache is
`3e1982d987461dc7b67a6e79afc84ceb21e4b2d3da03bcac1a20a461bf3f1bdb`.

Command:

```text
docker exec clamav-current-rust-build-20260911 \
  ctest --test-dir /tmp/clamav-asan-current-20260912 \
  --output-on-failure -E '^libclamav$'
```

Result: `100% tests passed, 0 tests failed out of 27`; total elapsed time was
500.89 seconds. This included the current ZIP late-member/ZIP64 suite, all
large-file evidence and admission controls, Rust integration, `clamscan`,
`clamd`, `freshclam`, `sigtool`, clamdscan controls, and both milter targets.
The retained build/test tree contained no `AddressSanitizer`,
`UndefinedBehaviorSanitizer`, `LeakSanitizer`, or runtime-error diagnostics.

The complete `libclamav` sanitizer target was intentionally excluded because
the prior authoritative run reached its configured 1,200-second timeout
without sanitizer diagnostics; that remains an explicit certified-runner/time
profile task, not a pass or a silent skip.

This is current-source ARM64 Docker development verification. It does not
qualify exact 32-GiB/materialized fixtures, certified Linux x86-64 resources,
production-CVD/service behavior, privileged fanotify, Sonic1, independent
format-8 execution, or final release readiness. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
