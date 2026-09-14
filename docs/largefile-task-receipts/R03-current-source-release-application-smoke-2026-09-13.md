# Task receipt: R03 current-source Release application smoke — 2026-09-13

Task ID / parent milestone: `R03` / `R10`.

The current-source Release `clamscan` binary was exercised in the existing
disposable `rust:1.97-bookworm` container
(`clamav-current-rust-build-20260911`). The source is mounted at `/src` and
the application was run from `/tmp/clamav-release-current-20260913`.

The binary reports:

```text
ClamAV 1.5.3-largefile-devel
```

With the repository test certificate directory explicitly supplied through
`--cvdcertsdir=/src/unit_tests/input/signing/verify` and the current Release
test HDB:

- `/src/README.md` returned exit `0` and `OK`.
- `unit_tests/input/clamav_hdb_scanfiles/clam.zip` returned exit `1` with
  `ClamAV-Test-File.UNOFFICIAL FOUND`.

The first attempt without `--cvdcertsdir` correctly failed closed because the
container has no `/usr/local/etc/certs`; that setup failure was corrected
without changing the binary or database. No sanitizer, database-load, or
scanner diagnostic appeared in the successful runs.

Retained identities:

- source manifest SHA-256: `4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`
- Release `clamscan` SHA-256: `3a59979b9987600aaf9590cece8ac51bd9e508d99808a652a73c61d0c89c754b`
- Release `CMakeCache.txt` SHA-256: `1f125879914959b31775438b6dbd865a1bf45e219c587c92ecd424df1d5b45e9`
- test HDB SHA-256: `e9649d9d3416df7802567063f88d8ff181795ed4e2bab827134c1707375df38c`

This is current-source ARM64 development smoke evidence only. It does not
qualify certified Linux x86-64, exact/materialized 32-GiB edges,
production-CVD/service, fanotify, independent format-8 bytecode, Sonic1, or
final release readiness. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.

State: `development-smoke-verified; qualification-blocked-by-external-runner-and-release-fixtures`.
