# Current-source exact-size PCRE receipt — 2026-10-08

## Outcome and scope

This is a separate, incomplete run on source manifest
`62f4dd75c1fbe535b4da5d6769d2f27b156462e4fe62348bee3d515d972e52d9`. Do not
merge it with the earlier complete R2 pair on manifest `d67cc5a…` documented
in the parent R2 receipt. The 62f4dd75 detection leg completed and its raw
process samples bind the peak directly to PCRE on the exact-size root. The
continuation leg was deliberately terminated after the existing container's
cgroup approached its memory ceiling on physical Sonic1. It has no final scan
report and is **incomplete**, notwithstanding a phase sidecar ending in
`complete`. No pass is claimed for the continuation, this source package, or
overall qualification.

The user authorized one isolated qualification using the custom seccomp
profile and explicitly cautioned that Sonic1 is physical hardware. The test
container alone used the profile; it allowed `userfaultfd` only when argument
0 equaled 526337, with default `SCMP_ACT_ERRNO`. No `seccomp=unconfined`, host
or Docker-daemon setting change, software installation, source edit, cleanup,
or new workload followed. After cancellation and termination of the identified
scanner process, the existing container was left running with only its
pre-existing `sleep infinity` process.

## Source, build, and fixture identity

- Source manifest content SHA-256:
  `62f4dd75c1fbe535b4da5d6769d2f27b156462e4fe62348bee3d515d972e52d9`.
- Deterministic source package: 18,502,394 bytes, SHA-256
  `93b54eda2d1ac74f1324eb11d9c7e0678bfd5017d7662c320c4d19cb798876bd`.
- Release build completed, job `job_9cfe116a0b61406ea1d83156de61dcfc`,
  exit 0. CMake cache SHA-256
  `5b08ea0d45cc536f99659cd2ea4ff2f9d1707b42a13e1a33f26165064af2199d`.
- Scanner SHA-256
  `101b2f3a99f5c166d7b2d00dc632b11ef09a3c930efe8bfd8f04471ea9a5f8ea`,
  reported version `ClamAV 1.5.3-largefile-devel`.
- Container ID
  `9176b0507f1b1b36e0a66e42e2e5a403bb3382b184a990434b9cdeff732cf864`,
  image SHA-256
  `c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Fixture `/fixture.zip`: exactly 34,359,738,368 bytes, SHA-256
  `450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`.
- Detection and continuation used distinct synthetic databases. Their SHA-256
  values are respectively `1b79d9b6436004f5e00d728303ece91d57b9232785685990126e1b0778343f0a`
  and `8f77f5744a5e40bd0884b65aed246834347988c96b73fd356618bc8d56574480`.
- The isolated container had network disabled, read-only root filesystem,
  dropped capabilities, no-new-privileges, unprivileged user, read-only source,
  fixture and database mounts, and writable build/evidence mounts.

## Detection leg — narrow pass

Job `job_1995569b988d48d1bfcd74656106f700` ran 2026-10-08 13:58:50–14:01:48
UTC. The scanner exited 1 as expected for the synthetic detection. The report
records `verdict=2`, `completion=DETECTION_TERMINATED`, and
`last_alert=PcreZipTail32G.UNOFFICIAL`; its `status=0` /
`status_name=No viruses detected` fields are inconsistent with that verdict
and alert and are preserved as a report-schema caveat, not interpreted as a
clean scan.

The raw RSS sample sequence 1531 is the whole-workload peak and identifies
`phase=pcre`, `object_id=0`, recursion 0, and `phase_subject_bytes=34359738368`.
Thus this measurement is bound to PCRE on the exact-size root, rather than
inferred from the validator. Peak process-tree RSS and PCRE RSS were both
31,970,388 KiB. That is 1,584,044 KiB below the strict 32-GiB whole-workload
limit (33,554,432 KiB), and 9,972,652 KiB below the distinct 40-GiB PCRE limit
(41,943,040 KiB). Root post-PCRE RSS was 54,768 KiB, safely below the strict
12-GiB limit (12,582,912 KiB). The expected synthetic signature was found at
byte 34,359,738,091, with no skipped operations.

This establishes only the detection leg for this source identity and
reproducer; it does not establish continuation or close blocker 1 on the
frozen release candidate.

## Continuation leg — incomplete and safety-stopped

Job `job_be13cf0d214f4909915d81d506a5bab2` began 2026-10-08 14:04:19.579 UTC.
Canceling its remote wrapper first returned exit 130 but did not stop its child
scan. Read-only process inspection identified ClamAV PID 32047 inside the
existing container; `SIGTERM` was sent only to that PID. Subsequent process
inspection showed only the container's pre-existing `sleep infinity`, and
container CPU returned to 0%. The container itself was not stopped or
restarted.

The reason for stopping was a conservative hardware-safety boundary, not a
roadmap RSS overage. A contemporaneous cgroup snapshot showed
`memory.max=51,539,607,552` bytes (48 GiB), `memory.current=50,331,303,936`,
`file=49,325,821,952`, and `anon=108,077,056`; the cgroup was close to its cap,
with most charge in file cache. This cgroup accounting is distinct from the
roadmap's process-tree RSS limit. The captured process-tree RSS peak was only
125,472 KiB and PCRE peak 94,092 KiB; the object-1 post-PCRE sample was
94,236 KiB. These partial measurements do not convert a canceled scan into a
pass.

The exercised subject was nested `prefix.bin`, object 1, recursion 1,
34,359,705,207 bytes—33,161 bytes smaller than the exact-size ZIP root. At
termination the resource row had 7,909 samples and its maximum was in
`deep-parse`; there is no `continuation-scan-report.json`, and the process log
has no normal final scan summary. The phase sidecar says `complete`, but that
marker conflicts with the absent report, truncated process log, and confirmed
termination and is not accepted as proof of completion.

Staging also nearly reached its separate 64-GiB limit: temporary peak
68,719,410,414 bytes versus 68,719,476,736, only 66,322 bytes of margin. The
temporary extracted file remains on Sonic1 at
`/tmp/clamav-qualification-disk-lv-v1/clamav-current-62f4dd75-20261008/evidence/current-source-62f4dd75-pcre-exact-root-20261008/temporary/continuation/clamav-5a2418bba50d2360a2e137e951867007.tmp`.
No remote or local copy was deleted.

## Qualification status and remaining work

- Blocker 1 remains **partial/open** for the frozen candidate. The complete
  R2 result on manifest `d67cc5a…` remains a separate narrow pass for that
  exact-size pair; this newer `62f4dd75…` identity has only a completed
  detection leg and an incomplete continuation. The historical R13
  33,779,368-KiB whole-workload peak remains unbound to an object. Do not
  generalize either result to the full workload matrix.
- Blocker 2: this source identity's guard/readiness and sanitizer evidence were
  not run here. A Release build succeeded; that is not sanitizer evidence.
- Blockers 3–5 remain open: capability-specific parser/matcher/ingress matrix;
  authorized production CVD and private canary; real fanotify permission,
  denial, cleanup, resource/concurrency evidence; actual-release defaults and
  release gate.
- No source file or frozen candidate was modified, no software installed, no
  container or evidence removed, no commit or push made, and the qualification
  goal state was not changed. No usage reset was used.

## Durable files

The source package, exact manifest, build cache identity, custom seccomp JSON,
configs, detection report/log/database, both RSS traces, both resource rows,
and phase sidecars are retained beside this receipt. Their local SHA-256
inventory is `SHA256SUMS.txt`. The local source package hash was recomputed
after download and matches the value above.
