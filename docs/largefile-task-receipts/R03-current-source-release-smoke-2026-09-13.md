# Task receipt: R03 current-source Release application smoke

Task ID / parent milestones: `R03` / `R10`, `R11`

The existing ARM64 Docker Release tree was reconfigured against the current
mounted repository after the R05 fixture-tool change. The source manifest
contains 1,697 entries and has SHA-256
`7c9e98e508dea7060cf515f952d734b311bd5be2bfeb3816b1cbcfb7a0eebf00`.
The existing build graph was then rebuilt with `cmake --build`; no compiled
target required source recompilation after the reconfiguration.

Build identity:

- CMake cache: `8ea09de25c6b880163078e9ed72759b08cafcb6ffc556538945723f4055b57d7`
- `clamscan`: `3a59979b9987600aaf9590cece8ac51bd9e508d99808a652a73c61d0c89c754b`
- `clamd`: `59ba066ee121c15a1792008be6f5b2973db311e7cb2e448a98c69a891e164c6d`
- `clamdscan`: `c977d808601e6f8c22fc93f3dee399d1be0d2a7e44783369993e639ef6c080b9`

Read-only smoke checks through the source-rebound Release `clamscan`
passed:

- `/src/README.md` returned `OK`.
- The checked-in hash fixture `clam.exe` returned the exact
  `ClamAV-Test-File.UNOFFICIAL FOUND` detection.

This is application smoke evidence on the local ARM64 development container,
not full-size or certified qualification. Exact 32-GiB/materialized cases,
certified Linux x86-64 resources, production databases, service/milter/
fanotify evidence, and final release readiness remain open. No capability was
promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
