# R13 resource capture process-log retention — 2026-09-20

Task ID / parent milestone: `R13 / R02-R04 resource evidence`.

Scope: make the resource-capture producer retain an optional merged scanner
process log, then exercise the current phase bridge and process-tree sampler in
one coherent bounded Sonic1 smoke. This is stale-tree development evidence;
it is not a qualification or capability-promotion record.

Implementation:

- `tools/largefile_acceptance_resource_capture.py` now accepts
  `--process-log` and captures the wrapped command's stdout and stderr into a
  bounded evidence-root artifact.
- The same capture now accepts `--sample-log` and retains an ordered,
  timestamped TSV trace with the wrapped process RSS, aggregate process-tree
  RSS, phase label, and sampled process count. The trace is written only after
  the independent procfs sample succeeds and fails closed on write, path, or
  sampler errors.
- Existing non-empty or symlinked process-log paths are rejected; the capture
  and sample-log paths are rejected; both streams close on startup, sampler,
  interruption, and normal completion paths. Focused regressions cover the
  new path hardening and timestamped trace format.

Local verification:

- Focused resource/phase tests passed 30/30.
- The full 604-entry source guard, release-readiness controls, snapshot check,
  and diff check passed.

Sonic1 smoke identity and boundary:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container:
  `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image:
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- `/src` was the read-write bind of
  `/tmp/clamav-32gb-current-20260915`.
- Only the current local `matcher.c` and the current capture wrapper were
  reconciled into the otherwise stale remote tree. The placeholder provenance
  manifest in this smoke is therefore not a current-source identity.

Coherent run result:

- The existing 8-GiB-minus-8-byte sparse fixture was scanned with the custom
  `PcreTail` signature. The exact fixture size was `8589934584` bytes, the
  fixture SHA-256 was
  `1d887622f47df15eb5d8bcb461f6412406abe8542ed9aa6a9c6cd62af80a12d8`, and
  the exact tail match was at offset `8589934576`.
- The tracked async wrapper reported 358 process-tree samples and published a
  resource row before returning exit 1 for the expected positive-control
  detection.
- Resource row: RSS peak `8426876 KiB`, PSS peak `8424042 KiB`, VAS peak
  `8476920 KiB`, swap `0 KiB`, temporary peak `0` bytes, PCRE phase peak
  `8426876 KiB`, post-PCRE phase peak `8271844 KiB`, and one stable OOM cgroup
  with zero OOM events and zero OOM kills.
- The phase file was exactly `pcre-start`, `post-pcre`, `complete` in order.
- The retained merged process log contains the object-bound runtime markers
  `deep-parse`, `before-pcre`, `pcre`, and
  `post-pcre-before-deep-parse`, with `subject_released=1` at the post-PCRE
  marker, plus the exact tail match and `PcreTail.UNOFFICIAL` detection.

Retained remote artifact hashes:

- Phase file:
  `a1917770ee2192298a3ac5d2f07c2f5f20d52f8189e8c5af65a2a20d60763c35`.
- Resource sidecar:
  `9ea0d6fb46e4a8ae0e5c5322532e35f09947f7c101b0826707dd5f059d346ced`.
- Merged process log:
  `c5eab8d9c335f9cbd96185ef9e0b7c36cfce255d471ee278c413a9baa64dfa40`.

Limits: the run does not prove current-source provenance, the 32-GiB case,
the strict release proof JSON with timestamped phase samples, sanitizer
parity, fanotify, production-CVD/service behavior, or release readiness. No
capability was promoted. No software was installed or downloaded, and no
GitHub workflow was triggered.

State: `development-verified; runtime-qualification-open`.

Follow-up sampler/phase audit (2026-09-20):

- The procfs sampler now obtains root-process RSS and aggregate tree RSS from
  the same process snapshot when `--include-root` is requested. The remote
  Linux procfs regression passed, and the local full tools suite passed 227
  tests with two expected Linux-only skips.
- A rebuilt Sonic1 `clamscan` smoke retained 190 ordered samples. Every
  retained sample had root RSS no greater than tree RSS; the resource row
  recorded RSS peak `8427004 KiB`, PSS peak `8424298 KiB`, VAS peak
  `8476916 KiB`, PCRE peak `8421196 KiB`, post-PCRE peak `8427004 KiB`, one
  OOM cgroup, and zero OOM events or kills. The exact `PcreTail.UNOFFICIAL`
  match remained at offset `8589934576`, with the expected scanner exit 1.
- This positive-control detection terminates before parser dispatch, so its
  application phase file is intentionally only `pcre-start`, `post-pcre`,
  `complete`; it does not prove the required post-release `deep-parse` phase.
  The capture producer was then corrected so terminal `complete` can never be
  relabelled as a synthetic `deep-parse` sample. The focused regression and
  source controls pass after that correction.

Latest smoke artifact hashes:

- Phase file:
  `a1917770ee2192298a3ac5d2f07c2f5f20d52f8189e8c5af65a2a20d60763c35`.
- Resource sidecar:
  `94e3e84cd1cbe880510a13bf3b1afac4878b633cd5856b48d7959702aae5106b`.
- Merged process log:
  `e9693f402c5a48ed3775b882d8cb38dd2f61891a7fa8e545a02a6b2596936797`.
- Timestamped sample trace:
  `ac7c8fd8fb53e927b04b3f30bd1eb3982e96ffcd4814ecffdefef5906dc65175`.

Nonmatching phase-order control:

- A disposable `PcreNoMatch` database was used against the same 8-GiB-minus-
  8-byte fixture. The scan completed cleanly (`OK`) after two full-map PCRE
  passes and retained 414 ordered samples with root RSS bounded by tree RSS.
- Its phase file was again exactly `pcre-start`, `post-pcre`, `complete`, and
  the sample trace contained only `before-pcre` and
  `post-pcre-before-deep-parse`. The runtime log shows the existing scanner
  ordering: the parser-dispatch `deep-parse` marker occurs before the raw PCRE
  pass, while the post-release marker occurs afterward. The wrapper therefore
  published no resource sidecar for this control, and it cannot satisfy the
  strict R13 phase proof.
- Phase file hash:
  `a1917770ee2192298a3ac5d2f07c2f5f20d52f8189e8c5af65a2a20d60763c35`.
  Process-log hash:
  `0916128feb9f76696d263ddb4c56e5f37a1a580ffe01e4b998002cdd39a462a7`.
  Sample-trace hash:
  `afe6b866c8933e2514a201f978035616d8bf26b084d5dc63d22df4bde7e95a1d`.

The latest smoke remains stale-tree development evidence because its remote
source/build/config identity artifacts were placeholders, and it is not a
32-GiB run or a formal R13 proof JSON. No capability was promoted.

Post-raw deep-parse boundary correction and clean-control revalidation
(2026-09-20):

- The scanner boundary was corrected so the application `deep-parse` marker is
  emitted only after the outer raw scan completes. The generic binary-data
  fallback is also suppressed after that raw scan, preventing a duplicate
  full-subject PCRE pass from contaminating the deep-parse interval.
- Local focused resource/procfs/phase tests passed 24/24. The 604-entry source
  guard and readiness control passed. The synchronized Sonic1 `scanners.c`
  hash was
  `c16345902a42b4b1ebb20ad8b70dde9acc79a1316c455243aa13410946753761`, and
  the remote CMake rebuild of `clamscan` exited 0.
- On the existing Sonic1 container, a fresh nonmatching 8-GiB-minus-8-byte
  clean control completed with `OK`. Its phase file was exactly
  `pcre-start`, `post-pcre`, `deep-parse`, `complete`. The merged runtime log
  contains exactly one full-map `matcher_run`, followed in order by
  `before-pcre`, `pcre`, `post-pcre-before-deep-parse` with
  `subject_released=1`, and `deep-parse` with `subject_bytes=0`.
- The independent sampler retained 175 ordered samples, with root RSS no
  greater than aggregate tree RSS. The run did not publish a resource sidecar:
  the PCRE and post-PCRE windows were shorter than the sampler interval, so no
  strict resource peak is claimed from this control. The sample trace contains
  only `before-pcre` and `deep-parse` rows for the same reason.

Clean-control artifact hashes:

- Phase file:
  `2346da2d0dab2183202bb4deebf910d7799f1099909a84cf5a37037525e5c5d1`.
- Merged process log:
  `a47701636e7f4c8e9d081859ee0d037bb698e0181b0f979a0a91e53615741435`.
- Timestamped sample trace:
  `7abc6df8da872ccb4633ee7125fdfa98d724ec4ac9277e82be9aaff1357fc95c`.

This is stronger development evidence for phase ordering and duplicate-PCRE
removal, but it remains stale-tree evidence and does not create a formal R13
proof JSON or promote any capability. Full-size 32-GiB, current-source
identity, resource-peak capture across every required phase, sanitizer,
fanotify, production-CVD/service, and release evidence remain open.

Phase-acknowledged boundary capture and clean-control revalidation
(2026-09-20):

- The qualification-only capture path now uses an explicit opt-in rendezvous:
  the watcher takes an independent procfs/tree metric at each application
  phase event, writes an acknowledgement, and the scanner waits only when
  `CLAMAV_LARGEFILE_RESOURCE_PHASE_ACK_FILE` is set. The normal production
  path remains unchanged when the environment variable is absent. OOM and
  temporary-file measurements remain owned by the regular sampler.
- The legacy C89-compatible remote rebuild of `clamscan` exited 0 after the
  matcher acknowledgement helper was added. The local focused resource,
  procfs, and phase suite passes 25/25; the full local tools suite passes 228
  tests with two expected skips; and the generated inventory was refreshed
  after the source changes.
- The remote container source hashes match the current local worktree for
  `libclamav/matcher.c`
  (`ead322410616254bc283d23a68967601cc05b86b240de0306f45720b68801bb2`),
  `tools/largefile_acceptance_resource_capture.py`
  (`7b7cf3061bc0f1cb6acca82b01d7cd5db54147329f7163e4a70d2e22838cbb5c`), and
  `libclamav/scanners.c`
  (`c16345902a42b4b1ebb20ad8b70dde9acc79a1316c455243aa13410946753761`).
- A fresh Sonic1 nonmatching clean control (`clean-13`) completed with `OK`
  against the exact 8-GiB-minus-8-byte fixture (size `8589934584`, SHA-256
  `1d887622f47df15eb5d8bcb461f6412406abe8542ed9aa6a9c6cd62af80a12d8`). The
  phase file is exactly `pcre-start`, `post-pcre`, `deep-parse`, `complete`,
  and the process log contains one full-map matcher run followed by the four
  expected runtime markers.
- The resource sidecar contains 340 ordered samples. It records
  `rss_peak_kb=8426796`, `pss_peak_kb=8423832`, `vas_peak_kb=8476916`,
  `pcre_rss_peak_kb=8426796`, `post_pcre_rss_peak_kb=8372540`,
  `oom_events_peak=0`, `oom_kill_events_peak=0`, and `swap_peak_kb=0`.
  The trace includes all four required sample labels, including the
  post-PCRE boundary before deep parsing.

Clean-13 artifact hashes:

- Phase file:
  `2346da2d0dab2183202bb4deebf910d7799f1099909a84cf5a37037525e5c5d1`.
- Resource sidecar:
  `c1fbf3535ae2320769f75b536b481ee19f41c85887bad9c087b215e6614e88aa`.
- Merged process log:
  `a47701636e7f4c8e9d081859ee0d037bb698e0181b0f979a0a91e53615741435`.
- Timestamped sample trace:
  `551cc6d9b3bf26bf5d7fc48c30c68e917e1c0eb5155344495ecb71f9a31e6654`.

This is materially stronger stale-tree development evidence, but it is not a
formal R13 qualification: the identity artifacts are still placeholder/stale
tree provenance, the run is not the exact 32-GiB fixture, and no formal proof
JSON, sanitizer, fanotify, production-CVD/service, or release evidence has
been assembled. No capability was promoted.
