# R04/R10 current-source service acceptance parity — 2026-09-14

The current dirty source at HEAD `8e837b88c89874b180a1a25f22d287f7d6be29db` was exercised in the retained ARM64 `rust:1.97-bookworm` container `clamav-current-rust-build-20260911`, using the reconfigured current-source build trees. This is small-fixture development evidence, not 32-GiB or certified release qualification.

## Source and build identity

The source manifest contains 1,697 entries and has SHA-256 `72d38dfa47fe40af62750cd89f2ebddd4ebae594fc29cb1e513b385f0a0c3803`. The Release CMake cache and build manifest both bind that hash; the ASAN/UBSAN cache and build manifest do likewise.

- Release build: `/tmp/clamav-release-current-20260913`; CMake cache SHA-256 `d2c88954e4b292f9e7825c83965b2ba701c0bff9f5144d79bfe0447c9f504b0c`.
- ASAN/UBSAN build: `/tmp/clamav-asan-current-20260912`; CMake cache SHA-256 `4cfbd43bec86acff15d33e3339ebc0ad43f61b56cbd0bf9df20ff2cee5d7f0f2`.

## Capture and records

`tools/largefile_development_service_capture.py` was run once against each current build with the checked-in repository test CA. Each capture wrote 36 R04 records and independently passed `largefile_acceptance_cases.py --check-records`:

- Release output: `/tmp/clamav-r04-service-release-current-20260914f`; command log SHA-256 `cc5a2a1d355a4eed414ac424426d690deebf828a265dd57f2e52ff09ef1fe84e`; acceptance-record TSV SHA-256 `4f41557ccbecf7d971731be5645d5420de1e5185a58a230676103bd599e9f71e`.
- ASAN/UBSAN output: `/tmp/clamav-r04-service-asan-current-20260914f`; command log SHA-256 `cc5a2a1d355a4eed414ac424426d690deebf828a265dd57f2e52ff09ef1fe84e`; acceptance-record TSV SHA-256 `58f1e299fd49c92b17f034a74eb4450b3fc95874c891f4eb0fcf9f10ca80e423`.

Each set covers the structured clamd `SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`, `ALLMATCHSCANREPORT`, `FILDESREPORT`, and `INSTREAMREPORT` commands plus clamdscan `default`, `fdpass`, `stream`, `multiscan`, `stream-multiscan`, and `fdpass-multiscan` modes. Every mode has clean, detection, and configured-limit records: 12 `COMPLETE`, 12 `DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE` outcomes. The records bind exact fixture/oracle/database/config/build/source identities and pass health, cleanup, and structured resource-phase validation.

The three lifecycle artifacts in each capture have the same SHA-256 `26c32553a1163c6069cb3e1cd657fdbc70a46876dcdcaaa1f5961d1c1b873e19`; each records successful pre/post PING, a present PID after startup, normal daemon exit, and removal of the socket and PID file. The ASAN/UBSAN capture logs contain no AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, or runtime-error diagnostic.

## Qualification boundary

This strengthens R04/R10 development evidence for current daemon and client ingress behavior. It does not prove exact/materialized 32-GiB inputs, production CVD coverage, certified Linux x86-64 resources, milter, privileged fanotify, PCRE phase RSS, Sonic1, independent format-8, or final release readiness. The authoritative repository records file remains intentionally empty; no capability was promoted. No software was installed, no usage reset was used, and no commit, push, or GitHub workflow action was performed.

State: `development-service-verified; qualification-open`.
