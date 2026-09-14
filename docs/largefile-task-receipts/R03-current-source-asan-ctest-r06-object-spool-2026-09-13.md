# R03/R06 current-source ASan/UBSan matrix after OneNote spooling — 2026-09-13

Task ID / parent milestones: `R03` / `R06`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE` and
`feature:onenote-modern-over-256m`; no capability status change.

## Scope and provenance

The current object-group payload spooling change was rebuilt in the existing
disposable ARM64 Docker build and exercised through the configured sanitizer
CTest matrix. The known long aggregate `libclamav` test was excluded with the
exact expression `^libclamav$`; that aggregate remains separately documented
as incomplete at its ARM64 duration limit.

- checkout: `/Volumes/512gbNVME/github-external/ClamAV-32gb`, branch
  `largefile-roadmap-qualification`; intentionally dirty working tree
  preserved;
- source manifest: 1,697 entries, SHA-256
  `3c8f5a0ecdb04aba70531067e35628ae95edad6c723bd9f08624f109ea41edd6`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- configuration: `RelWithDebInfo`, C and C++
  `-fsanitize=address,undefined -fno-omit-frame-pointer`,
  `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`, and
  `ENABLE_UNRAR=ON`;
- fresh `unit_tests/check_clamav` SHA-256:
  `fb80e2aaa45026af6037793e2b38d6fa82227ba6bce19f322b928e3f92b11eb3`;
- `CMakeCache.txt` SHA-256:
  `342f477d96232ca059ff9cee3bfe052fcfa584e216ee4b229fb83fc15dd43e25`;
- CTest `LastTest.log` SHA-256:
  `5f1fe7ca5cd7ed4bb98d88672cb3825f7c112efeadcda8c894c16bd26f0ca63b`.

## Verification

- `ctest --test-dir /tmp/clamav-asan-current-20260912 -E '^libclamav$'
  --output-on-failure` — exit 0; 27/27 tests passed in 531.55 seconds.
- The run included the focused OneNote/application controls, Rust, clamscan,
  clamd, milter, service, resource, source-guard, and acceptance checks.
- Sanitizer stderr and the retained CTest log contain no
  AddressSanitizer, LeakSanitizer, UndefinedBehaviorSanitizer, or
  `runtime error:` diagnostics.

## Qualification boundary

This is ARM64 development sanitizer evidence, with the aggregate `libclamav`
test intentionally excluded because its current ARM64 run remains duration
incomplete. It does not prove certified Linux x86-64, exact/materialized
32-GiB, production-CVD/service, resource/fanotify, independent format-8, or
final release qualification. No capability was promoted.

State: `development-verified; qualification-open`.
