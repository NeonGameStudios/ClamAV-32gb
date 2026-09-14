# Task receipt: R10 structured service capture

Task ID / parent milestone: `R10`.

Exact capability surface under review: direct clamd structured report modes and
the clamdscan `fdpass`/`stream` report clients.

This receipt records current-source ARM64 development evidence. It does not
promote any capability or replace certified Linux x86-64, sanitizer,
full-size, production-CVD, resource, Sonic1, or final release qualification.

Source manifest SHA-256: `04aa4a408357b560a7a6d139cc5ba382bfa1a8d74a3c19ff12005b9a4381c730`.

Build identity SHA-256: `29f2cd22d7622402c42c6a92559533ae53923c6834913ec592b350e11759e44d`.

Rebuilt ARM64 Release binary SHA-256 values: `clamd`
`e663583968dfe7b91da705b0fc913759d8810ec512195991b6f11a5e8cce68db` and
`clamdscan` `7ec20b8b5d1a0ceec6f005a50090e5ecdb2e79725018638086f2f88cc6735a3e`.

## Verification

The existing disposable `rust:1.97-bookworm` ARM64 container ran:

```text
python3 -B /src/tools/largefile_development_service_capture.py \
  /tmp/clamav-release-current-20260912/clamd/clamd \
  /tmp/clamav-dev-service-20260912c/out \
  --clamdscan /tmp/clamav-release-current-20260912/clamdscan/clamdscan \
  --source-root /src \
  --build-dir /tmp/clamav-release-current-20260912 \
  --cvd-certs-dir /src/certs
```

The capture wrote 24 R04-shaped records:

- 18 direct clamd records: `SCANREPORT`, `CONTSCANREPORT`,
  `MULTISCANREPORT`, `ALLMATCHSCANREPORT`, `FILDESREPORT`, and
  `INSTREAMREPORT`, each with clean, detection, and limit outcomes.
- 6 clamdscan records: `fdpass` and `stream`, each with clean, detection,
  and limit outcomes.
- The outcome distribution was 8 `COMPLETE`, 8
  `DETECTION_TERMINATED`, and 8 `LIMIT_INCOMPLETE`.
- Each of the three daemon lifecycle records proved PING before and after
  cases, clean shutdown, socket removal, and PID-file removal.
- `python3 -B tools/largefile_acceptance_cases.py --check-records
  --records /tmp/clamav-dev-service-20260912c/provenance/acceptance-cases.tsv
  --evidence-root /tmp/clamav-dev-service-20260912c` passed with 24 records.

The first attempt correctly failed closed because the test configuration did
not supply a code-signature certificate directory. Supplying the repository's
`/src/certs` test CA resolved that environment prerequisite; no software was
installed and no production database or deployment was used.

The retained evidence is outside the source tree at
`/tmp/clamav-dev-service-20260912c`. It is current-source ARM64 Release
evidence only; no capability was promoted.

State: `development-verified`; release qualification remains pending.
