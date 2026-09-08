# Task receipt: R10 structured daemon/client ingress and limit parity

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: `clamd:SCANREPORT`, `clamd:FILDESREPORT`,
`clamd:INSTREAMREPORT`, `clamdscan:fdpass`, and `clamdscan:stream`. The
records below are current-source ARM64 development evidence; they are not
R04 qualification records.

Starting commit and working-tree/source manifest identity:

- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`.
- Current dirty-worktree source manifest SHA-256:
  `f3717b1253d2f6425c0ddf072d1837cc76486abb76700af0c19540c3705c97e9`.
- Disposable ARM64 build cache:
  `/private/tmp/clamav-largefile-tests-static`.
- Build CMakeCache SHA-256:
  `5b9230277f9a7b53677cfc8abcb8d91dbad1450ab05454964449e29fec88b29e`.

Changes made in this slice:

- Added a shared known-size stream preflight to the structured `dsreport()`
  path. It preserves the direct stream sender's historical soft-fail result,
  while translating a known `StreamMaxLength` refusal into the populated
  `LIMIT_INCOMPLETE` client fallback.
- Added a socketpair regression that requires an over-limit regular stream to
  send no protocol command and return `CL_EMAXSIZE` through `dsreport()`.
- Recompiled the changed common object and relinked the disposable `clamd`
  and `clamdscan` binaries.

Build and input identities:

- Current ARM64 `clamd` SHA-256:
  `695f651a2fa6cf6aaedff0c7776e92c41de658ebfc7453663ffca40bc150410f`.
- Current ARM64 `clamdscan` SHA-256:
  `e7ca0ebd66720ce5aaa297e00517374f956bc5bdc7f47a3b53e09486b3cfa272`.
- Detection database `service.ndb` SHA-256:
  `ebfbc8f67bb59450a15cfdc27e4f6461162ba9e757acb166327c50d1f1fa5d8f`.
- Limit database `clean.ndb` SHA-256:
  `c19dcf071b3e51ca13f62b3e3514f049da4c6d0ff61b4442b384347604fc30a3`.
- Detection fixture `fixture.bin` SHA-256:
  `fbd427626beeec7d54a692aff04f0b24a947104f1e6a009458afaa7183570725`.
- Limit fixture `limit.bin` SHA-256:
  `6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326`.

Observed results:

- With the 64-MiB development profile and `AlertExceedsMax yes`,
  `clamdscan --ping=1:5` returned `PONG` with exit `0`; a clean path scan
  returned exit `0` and `COMPLETE`; the detection fixture returned exit `1`
  with `LargeFile.Service.Detection.UNOFFICIAL` at offset `15`.
- With an 8-byte profile, `AlertExceedsMax no`, and matched client limits,
  path, `--fdpass`, and `--stream` each returned exit `2` and one structured
  `LIMIT_INCOMPLETE` record. Each record reports status `24`, verdict `0`,
  root size `10`, zero logical/matcher/temporary bytes, one skipped
  operation, `max_file_size=8`, and the exact reason
  `Heuristics.Limits.Exceeded.MaxFileSize`.
- The three alerts-off report SHA-256 values are respectively:
  `c19b779e36c8c1d0c47e211116b54da78b8d9111f4cec4f35bacc400c5fe8140`
  (path),
  `fe71086c86015edc3728617c2633cfb5730a6c1ba6f5a6dfb0322e887ec1c4cc`
  (fd-pass), and the same `fe71086c86015edc3728617c2633cfb5730a6c1ba6f5a6dfb0322e887ec1c4cc`
  (stream; the serialized fallback is deterministic).
- The clean and detection report SHA-256 values are
  `9de24ba3a0b2b672d05c749887c89dbefa71bb6b099c5b932af67e4cc1735627`
  and `b0d6dd7d3b2fd9551280d2649fbd3de71f9c0a47e626717438400cad4a55c8c6`.

Verification scope:

- The changed common translation unit compiled and both current-source
  binaries relinked successfully in the cached Docker toolchain.
- The live smoke covered clean, exact detection, path limit, fd-pass limit,
  and stream limit behavior with structured JSON reports.
- The Check regression source is registered but its binary was not run because
  the cached test container does not provide `check.h`. No qualification claim
  is made from that omission.
- No Linux x86-64 Release/sanitizer run, exact 32-GiB materialized service
  run, production CVD, R04 acceptance record, or certified resource record was
  produced. The ARM64 development capture is not a substitute.

State: `development-verified`; release readiness remains blocked.
