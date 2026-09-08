# Task receipt: R10 IDSESSION multiscan limit-report parity

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: `clamd:FILDESREPORT`, `clamd:INSTREAMREPORT`,
`clamdscan:fdpass`, and `clamdscan:stream`, specifically through the
`clamdscan --multiscan` IDSESSION path. This is current-source ARM64
development evidence, not an R04 qualification record.

Starting identity:

- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`.
- Current dirty-worktree source manifest SHA-256:
  `434502e2ee0171543af650bb2efdb92c438d31c9fc295c49d56839122ded3549`.
- Disposable build cache: `/private/tmp/clamav-largefile-tests-static`.

Defect and change:

The IDSESSION callback called the low-level stream/fd-pass senders directly.
When a known-size input exceeded the client limit, their historical soft-fail
result was converted into a generic open/resource fallback, losing the input
size, configured limits, and exact limit reason. The callback now classifies
that known-size refusal as `CL_EMAXSIZE` and uses the populated fallback
serializer, matching serial report mode while preserving direct sender
compatibility.

The changed `clamdscan/proto.c` object was compiled and the current ARM64
`clamdscan` binary was relinked. Its SHA-256 is
`52d9e26eb0d1de76b610dc9971695996c99680acbcfb54784ccd16a4405355f3`.
The paired current ARM64 `clamd` SHA-256 is
`695f651a2fa6cf6aaedff0c7776e92c41de658ebfc7453663ffca40bc150410f`.

Observed matrix:

- A disposable daemon used `MaxFileSize 8`, `MaxScanSize 8`,
  `StreamMaxLength 8`, `AlertExceedsMax no`, one worker, and the isolated
  no-match database `clean.ndb`.
- `clamdscan --stream --multiscan /out/limit.bin` returned exit `2` and one
  structured report.
- `clamdscan --fdpass --multiscan /out/limit.bin` returned exit `2` and one
  structured report.
- Both reports have SHA-256
  `fe71086c86015edc3728617c2633cfb5730a6c1ba6f5a6dfb0322e887ec1c4cc` and
  report status `24`, verdict `0`, completion `LIMIT_INCOMPLETE`, target
  `/out/limit.bin`, root size `10`, zero logical/matcher/temporary bytes, one
  skipped operation, `max_file_size=8`, and reason
  `Heuristics.Limits.Exceeded.MaxFileSize`.
- The daemon remained healthy through both requests; its retained log SHA-256
  is `89fafd5e29921020e366d47a8c42c38272e5c14805fb969974dab08491fe1637`.

Verification scope:

- The first pre-fix run reproduced the generic report, and the rebuilt pair
  then passed the corrected matrix.
- Full source guards, inventory synchronization, and `git diff --check` remain
  required after this source change; no qualification claim is made here.
- No Linux x86-64 Release/sanitizer run, exact 32-GiB materialized service
  run, production CVD, R04 acceptance record, or certified resource record was
  produced.

State: `development-verified`; release readiness remains blocked.
