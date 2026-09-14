# R04/R10 current-source service and CLI capture — 2026-09-14

Task ID / parent milestone: `R04` / `R10`.

The current-source ARM64 Release binaries were exercised through the
development evidence producers using the retained
`clamav-current-rust-build-20260911` container. This is a small-fixture,
development-only capture; it does not claim certified Linux x86-64 or full
32-GiB qualification.

## Commands and results

The service producer ran:

```sh
python3 tools/largefile_development_service_capture.py \
  --clamdscan /tmp/clamav-release-current-20260913/clamdscan/clamdscan \
  --source-root /src --build-dir /tmp/clamav-release-current-20260913 \
  --cvd-certs-dir /src/unit_tests/input/signing/verify \
  /tmp/clamav-release-current-20260913/clamd/clamd \
  /tmp/clamav-dev-service-current-20260914d
```

It wrote and validated 36 R04 records: the six structured clamd commands
(`SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`, `ALLMATCHSCANREPORT`,
`FILDESREPORT`, and `INSTREAMREPORT`) across clean, detection, and
MaxFileSize-limit outcomes, plus clamdscan default, fdpass, stream, multiscan,
stream-multiscan, and fdpass-multiscan modes. Every service record reported
health `pass` and cleanup `pass`.

The clamscan producer ran:

```sh
python3 tools/largefile_development_acceptance_capture.py \
  --source-root /src --build-dir /tmp/clamav-release-current-20260913 \
  --cvd-certs-dir /src/unit_tests/input/signing/verify \
  /tmp/clamav-release-current-20260913/clamscan/clamscan \
  /tmp/clamav-dev-clamscan-current-20260914d
```

It wrote and validated 6 R04 records covering file and stdin clean, exact
detection, and MaxFileSize-limit outcomes. Every record reported health `pass`
and cleanup `pass`.

The same two producers were then run against the existing ASAN/UBSAN trees
`/tmp/clamav-asan-current-20260912/clamd/clamd`,
`/tmp/clamav-asan-current-20260912/clamdscan/clamdscan`, and
`/tmp/clamav-asan-current-20260912/clamscan/clamscan`, writing to
`/tmp/clamav-dev-service-asan-current-20260914d` and
`/tmp/clamav-dev-clamscan-asan-current-20260914d`. They wrote and validated
another 36 service records and 6 clamscan records with the same clean,
detection, and limit matrix; every record reported health `pass` and cleanup
`pass`, with no sanitizer diagnostic.

## Bound identities

- Working-tree HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db` (intentionally dirty).
- Producer source-manifest SHA-256: `b1955dbea032097610e1917cd70be7db4ffad87e20079d4ba7cc2d225f1a8bcc`.
- Release CMakeCache SHA-256: `1645995e25859b5563715da91a714a90691f688c7b4645dc55aaec7fae32f615`.
- Service build-identity SHA-256: `e172d2640ef0b80c5ad68268f9b610a4c8e48b1f28c320f9f88db766092e4951`.
- Service acceptance-record SHA-256: `dad7a2fe924cd2bb98270d80a9d20a498e58251dcff55ec7a585811463c432e0`.
- Clamscan acceptance-record SHA-256: `ad41feea18a17c9d06410de718205c98319d4627cb2888a65ca4df64cf7f878d`.
- ASAN/UBSAN CMakeCache SHA-256: `ade9a74d0690bb89fe2f2e4a060af9be20339e9632c1d58da5c840ae46cdb460`.
- ASAN/UBSAN service build-identity SHA-256: `e6ebe5d2e7014caba22d3915c08d54e2ff995ff834e377b16c08ed942d8c95a3`.
- ASAN/UBSAN service acceptance-record SHA-256: `9d60ff7cc873cb2dc59b04e583b68307dd0c6fc39ff007b2fa3ab3cd3953f775`.
- ASAN/UBSAN clamscan acceptance-record SHA-256: `549ac08573aa3efc61c57a8b3ce31a43395f4c41101d850b971d5394ca2c581b`.

The producer-enforced limits were the ARM64 development envelope (64 MiB
service fixture ceilings and bounded development resource markers), not the
release contract's exact/materialized 32-GiB cases. The records remain outside
the source tree under `/tmp`; no development record was copied into the
authoritative release acceptance manifest and no capability was promoted.

Remaining R10/R11 requirements include certified x86-64, production CVDs,
full-size/materialized fixtures, measured resource phases, Sonic1, and final
release review. No software was installed, no usage reset was used, and no
commit, push, or GitHub workflow action was performed.
