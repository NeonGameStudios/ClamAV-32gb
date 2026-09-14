# Task receipt: R10 daemon receive deadline edge

Task ID / parent milestone: `R10`.

Exact capability under review: `clamd:INSTREAM`.

This receipt records a focused ARM64 development verification. It does not
promote the capability or replace certified Linux x86-64 qualification.

Source manifest SHA-256: `04aa4a408357b560a7a6d139cc5ba382bfa1a8d74a3c19ff12005b9a4381c730`.

Rebuilt ARM64 Release binary SHA-256 values: `clamd`
`e663583968dfe7b91da705b0fc913759d8810ec512195991b6f11a5e8cce68db` and
`clamdscan` `7ec20b8b5d1a0ceec6f005a50090e5ecdb2e79725018638086f2f88cc6735a3e`.

## Change

The daemon receive loop now treats a descriptor as expired when
`now >= timeout_at`, rather than waiting for a later polling interval after
the configured deadline. The existing zero sentinel remains the explicit
`ReadTimeout=0` no-deadline behavior. The stale `ReadTimeout` TODO was removed,
and the source guard now pins both the sentinel contract and inclusive
deadline comparison.

## Verification

- Inside the existing disposable `rust:1.97-bookworm` ARM64 container,
  current-source Release `clamd` and `clamdscan` rebuilt successfully with
  `cmake --build ... --target clamd clamdscan -j2`.
- The registered current-source `clamd` CTest target passed `1/1` in `36.81`
  seconds. Its 18 Python cases include legacy and structured
  `ReadTimeout=0` partial-stream pause/resume coverage plus the positive
  deadline-boundary regression.
- The repository source-guard sweep passed, including the generated
  inventory/readiness and 597-capability checks.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` passed.
- `git diff --check` passed.

The development result remains non-qualifying: certified Linux x86-64,
sanitizer, full-size, production-CVD/service, resource, Sonic1, R04 records,
and final release evidence remain open. No reset, remote SSH action, host
software installation, commit, push, or GitHub workflow action was used.

State: `development-verified`; release qualification remains pending.
