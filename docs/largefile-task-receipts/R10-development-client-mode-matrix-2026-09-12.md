# Task receipt: R10 development clamdscan client-mode matrix — 2026-09-12

Task ID / parent milestone: `R10` / `R00`.

Scope: bind all six required clamdscan client modes to distinct R04
capabilities and exercise each mode through the current-source daemon. This
is development-only ARM64 evidence; it does not promote a capability or
replace certified service qualification.

## Changes

The capability manifest now explicitly tracks the four previously unrepresented
R10 combinations: `clamdscan:default`, `clamdscan:multiscan`,
`clamdscan:stream-multiscan`, and `clamdscan:fdpass-multiscan`. The existing
`clamdscan:fdpass` and `clamdscan:stream` rows remain separate. The reviewed
case map now gives every row its own clean, detection, and limit case IDs.

`tools/largefile_development_service_capture.py` represents the CLI options as
tuples, so the combination cases are emitted as their actual option sets:

- `default`
- `fdpass`
- `stream`
- `multiscan`
- `stream-multiscan` (`--stream --multiscan`)
- `fdpass-multiscan` (`--fdpass --multiscan`)

The record binding uses the mode name, not the option tuple. A focused harness
regression covers the six-mode mapping.

## Verification

Container: `clamav-current-rust-build-20260911`, image
`rust:1.97-bookworm`; build directory:
`/tmp/clamav-release-current-20260912`.

Current-source binaries:

- `clamd` SHA-256:
  `e663583968dfe7b91da705b0fc913759d8810ec512195991b6f11a5e8cce68db`;
- `clamdscan` SHA-256:
  `7ec20b8b5d1a0ceec6f005a50090e5ecdb2e79725018638086f2f88cc6735a3e`.

Capture source manifest SHA-256:
`2d87dd801671fdd48a3b4cdab9fac26f6f758ff3637ff02a6dc06471b3af685e`.
Capture build-identity SHA-256:
`29f2cd22d7622402c42c6a92559533ae53923c6834913ec592b350e11759e44d`.

The fresh command wrote 36 records to
`/tmp/clamav-dev-service-20260912i/provenance/acceptance-cases.tsv`:

- 18 direct clamd structured-report records across
  `SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`, `ALLMATCHSCANREPORT`,
  `FILDESREPORT`, and `INSTREAMREPORT`;
- 18 clamdscan records across the six client modes above;
- 12 `COMPLETE` clean outcomes, 12 `DETECTION_TERMINATED` outcomes, and
  12 `LIMIT_INCOMPLETE` outcomes;
- detection records bind the exact
  `LargeFile.R04.Service.Detection.UNOFFICIAL` alert at offset `19`;
- each limit record binds the exact configured MaxFileSize outcome;
- every case retains daemon PING-before/after, lifecycle cleanup,
  fixture/database/oracle identity, and development resource-envelope data.

The independent verifier reported:

```text
large-file acceptance record schema passed (36 records)
```

Focused mode tests passed `8/8`, the case map check passed for `601`
capabilities, the status snapshot freshness check passed, and `git diff
--check` passed.

Qualification boundary: this proves the six client option combinations are
implemented and distinguishable on the current ARM64 development build. It
does not establish full-size behavior, production CVD parity, certified Linux
x86-64, sanitizer/resource evidence, privileged fanotify behavior, Sonic1
release evidence, or final readiness. No capability was promoted.
