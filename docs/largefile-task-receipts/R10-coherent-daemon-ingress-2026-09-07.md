# Task receipt: R10 coherent daemon/client ingress smoke

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: `clamd:SCAN`, `clamd:MULTISCAN`,
`clamd:INSTREAM`, `clamd:FILDES`, `clamdscan:stream`, and
`clamdscan:fdpass`. This is development evidence for the shared daemon/client
path, not a capability qualification record.

Starting commit and working-tree/source manifest identity:

- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`.
- Current dirty-worktree source manifest SHA-256:
  `6f6378133aedef71bc838584a598add97411efc20efe32d5d0234bc583cb6bb4`.
- Existing disposable ARM64 build cache:
  `/private/tmp/clamav-largefile-tests-static`.
- Existing build CMakeCache SHA-256:
  `5b9230277f9a7b53677cfc8abcb8d91dbad1450ab05454964449e29fec88b29e`.

Prerequisites verified:

- The cached ARM64 Docker toolchains were available; no host installation was
  performed.
- The test database and fixture were already present outside the source tree.
- The daemon was configured with one worker, queue depth two, and explicit
  development-sized limits.

Owned files and excluded shared files: current-source daemon/client objects
and the disposable build archive only; no release manifest, GitHub workflow,
or production deployment was changed.

Observed failing case and expected behavior: relinking current `clamdscan`
against the existing static archive initially failed because current
`clamdscan/proto.c` referenced `cli_scan_report_set_fallback_details`, while
the stale archive did not contain that symbol. The expected behavior is a
coherent current-source daemon/client pair with structured-report support.

Changes made:

- Recompiled current `clamd/scanner.c`, `clamdscan/proto.c`,
  `common/clamdcom.c`, and `libclamav/scan_report.c` objects.
- Refreshed the disposable `common` and `libclamav` archives.
- Relinked current `clamd` and `clamdscan` binaries.
- The source-level stream client now uses the shared bounded default when no
  clamd option table is supplied; its direct API regression is recorded in the
  companion R10 development receipt.

Commands, exits, logs and fixture/database hashes:

- Current ARM64 `clamd` SHA-256:
  `8dee7c4eb098b64caee4599a9593d3d3e1421147858495696ad53a19413d1006`.
- Current ARM64 `clamdscan` SHA-256:
  `a1570b7705b28fdcc2d0a520f66a91bb8dfc552d683481bbffc7ce12c7c57391`.
- `service.ndb` SHA-256:
  `ebfbc8f67bb59450a15cfdc27e4f6461162ba9e757acb166327c50d1f1fa5d8f`.
- `fixture.bin` SHA-256:
  `fbd427626beeec7d54a692aff04f0b24a947104f1e6a009458afaa7183570725`.
- Native-temp daemon smoke exit: `0`.
- `clamdscan --ping=1:5`: `PONG`, exit `0`.
- Path, `--stream`, `--stream --multiscan`, `--fdpass`, and `--multiscan`
  scans each returned the exact `LargeFile.Service.Detection.UNOFFICIAL FOUND`
  result with exit `1`.
- Retained daemon log SHA-256:
  `2262af76a05056eb75afbe1e098cef21c34a22ac34686afc0986e71ecdfab697`.

Development tests passed: current-source scanner version/help smoke, real
archive detection control, direct NULL-options stream API smoke, and the full
`largefile_source_guards.sh` suite. Inventory synchronization and
`git diff --check` also pass.

Full-size/certified evidence produced, or explicitly not run: no Linux
x86-64 Release/sanitizer run, exact 32-GiB materialized service run,
production CVD, R04 acceptance record, or certified queue/resource record was
produced. ARM64 development evidence is not a substitute.

Remaining failures / next slice: retain the coherent records on the authorized
Linux x86-64 runner, then execute the R04-bound clean/detection/limit/error
matrix and the full-size service oversize probe. R09 required rows, R11–R14
evidence, and final readiness remain open.

State: `development-verified`; release readiness remains blocked.
