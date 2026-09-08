# Task receipt: R10 single-worker streamed queue behavior

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: `clamd:INSTREAM` and `clamdscan:stream`.
This is current-source ARM64 development evidence, not an R04 qualification
record.

Starting identity:

- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`.
- Pre-receipt dirty-worktree source manifest SHA-256:
  `c37a17e561e5af137e00ba68b52bec681f9fce6be682667737c4f06717f79e6d`.
- Disposable build cache: `/private/tmp/clamav-largefile-tests-static`.
- Current ARM64 `clamd` SHA-256:
  `695f651a2fa6cf6aaedff0c7776e92c41de658ebfc7453663ffca40bc150410f`.
- Current ARM64 `clamdscan` SHA-256:
  `52d9e26eb0d1de76b610dc9971695996c99680acbcfb54784ccd16a4405355f3`.

Observed matrix:

- A fresh daemon used one worker, queue depth two, 64-MiB `MaxFileSize`,
  64-MiB `StreamMaxLength`, and the existing no-match control database.
- Two `clamdscan --stream --report-json` clients were started concurrently
  against the same exactly 67,108,864-byte control fixture.
- Both clients completed with exit `0`. Each report was exactly one JSON
  object with status `0`, verdict `0`, completion `COMPLETE`, and root size
  `67,108,864`.
- The daemon log recorded repeated
  `INSTREAM admission pending: waiting for an available scan worker` and
  matching `INSTREAM admission available: mode -> MODE_COMMAND` transitions.
  It also recorded two `THRMGR` dispatches with `active=0 queued=1` under the
  one-worker/two-queue profile. No request was rejected or left staged after
  completion.

Artifact hashes:

- Fixture: `3b6a07d0d404fab4e23b6d34bc6696a6a312dd92821332385e5af7c01c421351`.
- Client 1 report:
  `79e25ce332d2ef571ea85bfc73054e74be820b7ae87c33f0a3434792cf80af08`.
- Client 2 report:
  `b85f5df23b2789b1feeaf12c662319c552da2060db6d5f885fbc081c3c71ca75`.
- Retained daemon log:
  `72ddf054d0cf331d6f836b92bf9f9504c2a0ae6cbe70d2f3ed3d9329f79a2ed5`.
- Admission pending transitions: `16174` observed; available transitions:
  `16174` observed.

The cached image did not contain `/usr/bin/time`, so timing and RSS were not
claimed from this run. The daemon admission transitions and report outcomes
are retained as bounded development behavior only; certified queue/resource
evidence still requires the authorized Linux x86-64 runner.

Verification scope:

- `queue_report_matrix=pass`.
- Both client status files recorded `0`.
- `git diff --check` and the repository source guards passed before this
  receipt was added.
- No Linux x86-64 Release/sanitizer run, exact 32-GiB materialized service
  run, production CVD, R04 acceptance record, or certified resource record
  was produced.

State: `development-verified`; release readiness remains blocked.
