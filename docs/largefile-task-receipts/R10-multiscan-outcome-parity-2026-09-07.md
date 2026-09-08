# Task receipt: R10 IDSESSION multiscan clean/detection parity

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: `clamdscan:fdpass` and
`clamdscan:stream`, through the `clamdscan --multiscan --report-json`
multiscan behavior. Stream and fd-pass use the client IDSESSION path; the
path case uses the daemon MULTISCAN command. This is current-source ARM64
development evidence, not an R04 qualification record.

Starting identity:

- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`.
- Pre-receipt dirty-worktree source manifest SHA-256:
  `1affc5871d47ce04d226c7aaa6e883e9f1035f0b1b30bd0fa592f665641340f3`.
- Disposable build cache: `/private/tmp/clamav-largefile-tests-static`.
- Build CMakeCache SHA-256:
  `5b9230277f9a7b53677cfc8abcb8d91dbad1450ab05454964449e29fec88b29e`.

Observed matrix:

- A current-source ARM64 `clamd`/`clamdscan` pair was run in the cached
  `rust:1.97-bookworm` Docker image; no host software was installed.
- Detection used `service.ndb` and `/out/fixture.bin` (33 bytes). Path,
  stream, and fd-pass multiscan each returned exit `1`, completion
  `DETECTION_TERMINATED`, status `1`, verdict `2`, and the exact alert
  `LargeFile.Service.Detection.UNOFFICIAL` at offset `15`.
- Clean used `clean.ndb` and a four-byte `/out/clean-small.bin` under the
  eight-byte development limit. Path, stream, and fd-pass multiscan each
  returned exit `0`, completion `COMPLETE`, status `0`, verdict `0`, and no
  alert.
- The report matrix parser checked one JSON object per mode and matched the
  completion, exit, and exact alert relationships. All six cases passed.
- Client log checks found the exact detection line for all three detection
  transports and `OK` for all three clean transports; no unexpected
  detection appeared in the clean logs.

Artifact hashes:

- Current ARM64 `clamd`: `695f651a2fa6cf6aaedff0c7776e92c41de658ebfc7453663ffca40bc150410f`.
- Current ARM64 `clamdscan`: `52d9e26eb0d1de76b610dc9971695996c99680acbcfb54784ccd16a4405355f3`.
- Detection reports: path `7b2ca258740ff6c5c99cc6f828eabb689fc5000b3e887fbf30b46bef7f6caa2c`,
  stream `7720752b3c018206d8c674f5b6999d86b9ad1d507661ae7e16e8512b2f5d7cc6`,
  fd-pass `f6126c8793d45fa0d912cd1bc767014b860a6857154da5f0ae6324cb8532694a`.
- Clean reports: path `ffe0b81bc82436c3c7ef7c9c9f7e79bf8a72f67e9a5a84d415efb124d7280b71`,
  stream `938af840b3ba4ecf551eb10a1fd278098f82ad3529da7c9a4e74a93a72eedf3d`,
  fd-pass `8075312a008fa5fc04e2296fd0da225fa10ff684c923928732c060780afc405a`.
- Retained daemon logs: detection
  `4549304ebfcdaabe2e9d9b173d98c5a7affef9c063d777417a75c5eb5c3469cd`; clean
  `33830ac4109920bb46a18f50db77f9e1e29611c90651d50af22a84ebc42699b0`.

No source defect was found in this slice. It confirms the previous
IDSESSION limit-report fix did not disturb clean or exact-detection outcomes
across path, stream, and fd-pass multiscan ingress.

Verification scope:

- `multiscan_report_matrix=pass`.
- Exact client-log outcome checks passed.
- `git diff --check` passed before this receipt was added.
- Full source guards and inventory synchronization passed after this receipt
  was added; the final `git diff --check` also passed.
- No Linux x86-64 Release/sanitizer run, exact 32-GiB materialized service
  run, production CVD, R04 acceptance record, or certified resource record
  was produced.

State: `development-verified`; release readiness remains blocked.
