# R05 ARM64 oversized-admission blocker — 2026-09-13

## Scope

Attempt the roadmap's current-source sparse 32-GiB+1 `FILDESREPORT` probe with
the existing Release daemon. The daemon profile was corrected to the build's
accepted limits (`MaxFileSize`, `MaxScanSize`, `MaxContiguousSize`,
`PCREMaxFileSize`, and `StreamMaxLength` at 32G), with the known-good
development database and repository test CA.

## Provenance

- Source manifest: `4ff6260cf89396c0d4a5c96c889b89558cab599e33c4b26976921ce629749efc`
- Build: `/tmp/clamav-release-current-20260913`
- Daemon: `/tmp/clamav-release-current-20260913/clamd/clamd`
- Runner: existing disposable `rust:1.97-bookworm` ARM64 Linux container
- Database: `/tmp/clamav-r04-service-release-current-20260913/db/clean`
- CVD certificates: `/src/unit_tests/input/signing/verify`

## Result

The daemon parsed the profile and initialized the current-source engine, then
failed closed before creating its service socket or accepting the descriptor:

```text
ERROR: Large-file daemon admission failed: certified large-file daemon admission is limited to Linux x86-64
```

No sparse fixture was counted as scanned evidence, no acceptance record was
created, and no capability status was promoted.

## Next action

Repeat the exact probe on the authorized certified Linux x86-64 runner with
the required memory and disk preflight. The ARM64 development container cannot
satisfy this explicit platform gate; do not bypass it or relabel this attempt
as qualification.
