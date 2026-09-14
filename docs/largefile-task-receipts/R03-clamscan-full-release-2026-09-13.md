# Task receipt: R03 full `clamscan` Release integration — 2026-09-13

Task ID / parent milestone: `R03` / `R00`.

Scope: run the complete current-source `clamscan` application integration
target, including the parser corpus, application controls, R09 policy cases,
and the corrected UnRAR integration test.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used.

Environment: fresh current-source ARM64 Release build in Docker at
`/tmp/clamav-release-current-20260913`. The `clamscan` executable SHA-256 is
`351d24dbc01e71a13e8bc68ad2c39cd7aec72d52b42bc1b3d9119ab40f7543d2`; the
Release `CMakeCache.txt` SHA-256 is
`573f50cd1e93de777849a8489bc2d4c233c9de76ad03297c001958a20b196608`.

Verification command:

```text
ctest --test-dir /tmp/clamav-release-current-20260913 -V -R '^clamscan$'
```

Result: the CTest target passed 1/1 in 16.07 seconds. Its underlying Python
integration suite ran 127 tests with zero failures and zero errors, with one
expected platform skip. The run included the current parser corpus and the
application-level fuzzy-image, parser-policy, ignored-type, and corrected
RAR/RAR-SFX cases.

Qualification boundary: this is current-source ARM64 Docker Release
development evidence only. It does not prove certified Linux x86-64
execution, exact 32-GiB/materialized resources, production CVD/service
behavior, sanitizer or resource qualification for the full CLI suite, Sonic1
execution, or final release qualification. No capability was promoted.

State: `development-verified`; the complete current-source `clamscan`
integration target passed on the fresh Release build.
