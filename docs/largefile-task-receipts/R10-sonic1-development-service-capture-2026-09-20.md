# Task receipt: R10 Sonic1 development service capture

Task ID / parent milestone: `R10` / `R04`

Exact capability kind:id list:

- `clamd:SCANREPORT`, `clamd:CONTSCANREPORT`,
  `clamd:MULTISCANREPORT`, `clamd:ALLMATCHSCANREPORT`,
  `clamd:FILDESREPORT`, `clamd:INSTREAMREPORT`
- `clamdscan:default`, `clamdscan:fdpass`, `clamdscan:stream`,
  `clamdscan:multiscan`, `clamdscan:stream-multiscan`,
  `clamdscan:fdpass-multiscan`

Scope: exercise the current daemon's six direct structured-report modes and
the six supported `clamdscan` client modes against clean, exact-detection and
size-limit development fixtures. This is development evidence only; it is not
full-size, sanitizer, production-CVD, fanotify, or release qualification.

Starting source/build identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted at `/src`.
- Mounted snapshot Git identity: `08b3ab820e40ac8bd307290b0c78c03c94884f1b`
  (`temporary remote test snapshot`). The seven service-entry/tool source
  files used by this capture had byte-for-byte SHA-256 parity with the local
  post-PCRE candidate; the snapshot's receipt-only metadata was not used as
  executable source identity.
- Build directory: `/src/build-roadmap-20260920`.

Prerequisites verified:

- Fresh `clamd`, `clamdscan`, `clamonacc`, and `clamav-milter` front-end build
  had already completed successfully in this container.
- The disposable source snapshot's stale capability manifest and case map
  were replaced with the local candidate versions and verified by hash:
  `docs/largefile-capabilities.tsv` =
  `a007721cdb375beec591e13aee42adf7eefd9a2b712b6dbe324b2a67b736cb53`, and
  `docs/largefile-capability-case-map.tsv` =
  `ead341ca8edcf14ec217debfba0ac3e1479645cc42befdf3eb095fcf2081d743`.

Observed issue and correction:

- The first capture reached its final validator but failed with
  `acceptance map case requirements do not match the reviewed routing rules`.
  The application cases had run; the disposable snapshot's capability TSV
  and case map were stale relative to the local reviewed map.
- After exact metadata synchronization, the same tracked matrix was rerun
  without changing the producer, limits, expected outcomes or verification
  rules.

Command and result:

```text
docker exec 53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9 \
  python3 -B /src/tools/largefile_development_service_capture.py \
  /src/build-roadmap-20260920/clamd/clamd \
  /tmp/clamav-r04-service-sonic1-20260920 \
  --clamdscan /src/build-roadmap-20260920/clamdscan/clamdscan \
  --source-root /src --build-dir /src/build-roadmap-20260920 \
  --cvd-certs-dir /src/unit_tests/input/signing/verify
exit=0
development service capture wrote 36 R04 records
```

The capture's validator checked exact capability/case identity, structured
completion and verdict, fixture/oracle/database/build/source hashes, exact
detection signatures and offsets, health, cleanup and development resource
budgets. The retained `acceptance-cases.tsv` contains 37 lines (header plus 36
records).

Retained evidence outside the container:

- Host path: `/tmp/clamav-r04-service-sonic1-20260920-complete`.
- `acceptance-cases.tsv` SHA-256:
  `856f32ad6f67c2866ccefc510a41bcaa1ae225d7033659b15f546179397c04c9`.
- `source-manifest.txt` SHA-256:
  `c0a90d9b95294106f79a84d33b924ad8e2411d1748ce0e363ee380f1387e41b3`.
- `build-identity.txt` SHA-256:
  `f504fc44332a917f6d2eed9d57212290dc40fa7d0b1471146cf3f1073e2000a2`.

Interpretation and remaining work:

- Current-source daemon/client behavior and the R04 record binding work for
  these 12 ingress identities under the bounded 64-MiB development envelope.
- The 36 records do not cover the non-report direct modes, milter, on-access,
  full-size materialized edges, sanitizer parity, production CVDs, resource
  phases, or release readiness. No capability was promoted.
- The certified 32-GiB daemon admission remains separately blocked by Sonic1's
  available disk-backed temporary capacity.

State: `development-verified; certified-capacity-and-release-evidence-open`
