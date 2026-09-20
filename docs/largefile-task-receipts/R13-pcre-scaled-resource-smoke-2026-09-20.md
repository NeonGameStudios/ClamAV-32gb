# Task receipt: R13 scaled PCRE resource smoke

Task ID / parent milestone: `R13` / `R04`

Scope: run the current Sonic1 build against an 8-GiB-minus-8-byte sparse
fixture with an exact tail PCRE signature while sampling the complete process
tree through `/proc`. This is development evidence only; it is not the
32-GiB qualification run and does not promote `matcher:pcre`.

Environment and identity:

- Source commit used by the remote build: `e9032cb681d5881444d81cdd60e22a27c197f8b2`.
- Container ID:
  `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`
- Image ID:
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- The container mounted the current remote build tree at `/src`.
- The scaled run used `clamscan` from `build-roadmap-20260920`, the checked-in
  CVD certificate directory, `PCREMaxFileSize=8G`, `MaxScanSize=8G`,
  `MaxTemporarySize=64G`, and `MaxContiguousSize=32G`.

Workload and retained artifacts:

- Fixture size: `8589934584` bytes.
- Exact tail marker: `TAILMARK` at offset `8589934576`.
- Fixture SHA-256:
  `1d887622f47df15eb5d8bcb461f6412406abe8542ed9aa6a9c6cd62af80a12d8`
- Signature SHA-256:
  `8ab6f408dce9737e01980281d8d7ad2bed5b202325531af6d5026f12128acda9`
- Process-log SHA-256:
  `085b766f49a0aca4222a1f4c9a5d3ee613b6ab7890a32e637dec4b443e9d13f2`
- RSS sample TSV SHA-256:
  `54943861433eb72aefd7312b780f6c1ff9ac07e01b4f3a503a3a0f259c7c4eba`
- JSON report SHA-256:
  `4a57ee810c5dc1b92403a012df6e4fbf0fa98a29d226551ababfc84bb57a895f`

Observed result:

- The structured report returned `DETECTION_TERMINATED`, exit status 1,
  `root_size=8589934584`, `logical_bytes=8589934584`,
  `temporary_bytes=0`, and `last_alert=PcreTail.UNOFFICIAL`.
- The debug log recorded the exact match at `8589934576` and the ordered
  PCRE-local markers `before-pcre`, `pcre`, and
  `post-pcre-before-deep-parse`, with `subject_released=1` at the latter.
- The scan report elapsed time was `41361` ms.
- The procfs sampler retained 128 process-tree samples. Corrected maxima were
  RSS `8426136 KiB`, PSS `8423456 KiB`, VAS `8476788 KiB`, and swap `240 KiB`.

Limitations and cleanup:

- The MCP-SSH async envelope reported `timed_out` with supervisor exit 124 at
  its 15-second ceiling; the retained inner scan completed and no clamscan
  process remained when inspected. The envelope status is therefore recorded
  as an orchestration limitation, not treated as an authoritative job exit.
- The sample phase labels are not sufficient for the fail-closed PCRE proof:
  the log contains an earlier `deep-parse` marker before the PCRE-local
  markers, and no formal `pcre-rss-phase-evidence.json` was produced.
- This run did not exercise the 32-GiB subject, the `<12-GiB` post-PCRE gate
  before deep parsing, certified admission, sanitizer evidence, or release
  readiness.
- The disposable fixture and evidence remain under the remote current-source
  mount for audit; no production deployment was changed.

State: `development-verified`
