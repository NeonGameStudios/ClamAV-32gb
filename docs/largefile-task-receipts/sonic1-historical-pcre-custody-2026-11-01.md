# Historical 32-GiB PCRE continuation findings and evidence custody

Recorded 2026-11-01. This is historical, source-bound diagnostic evidence,
not a qualification pass for a later source tree or the RAM-resident
Stored-ZIP scanner.

## Scope and identities

Both October 8 experiments used the deterministic Stored-ZIP fixture whose
outer file size was 34,359,738,368 bytes (32 GiB) and SHA-256 was
`450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a`.
The large stored `prefix.bin` member was 34,359,705,207 bytes. The earlier
fixture construction and its separate input-mutation caveat are documented in
the [R11 fixture receipt](https://github.com/NeonGameStudios/ClamAV-32gb/blob/641ad1744fe02b4e79dcdaf501a4f1717f57bcb3/docs/largefile-task-receipts/R11-zip-exact-32g-fixture-2026-10-02.md).
Do not transfer conclusions between the October 8 source identities.

### E1513158

- Frozen source-manifest SHA-256:
  `e15131580aa2e7903e476580730fbbf9142c582df2efef4149769ff66ff48a3f`.
- Source package SHA-256:
  `d3a5a8a71ea0f8f3a560d28ff4f1fbad8c363dd770acce9ad8c4dd58942473ed`.
- The isolated detection leg completed with scanner exit 1 and the expected
  `PcreZipTail32G.UNOFFICIAL` detection. Whole-workload and PCRE peak RSS
  were 32,013,972 KiB; recorded post-PCRE RSS was 53,936 KiB.
- The continuation was interrupted as its 48-GiB, zero-swap container
  approached its cgroup memory ceiling. The scanner exited -15, its capture
  helper exited 143, and no normal continuation scan report was produced.
  The cgroup had 33,243 max-pressure events but zero OOM and OOM-kill events.
  A phase sidecar's completion marker does not override those results.
- Observed continuation process RSS was far lower than the cgroup charge,
  which was dominated by file cache. This is an incomplete diagnostic, not
  a full scan or a pass of the 32-GiB workload limit.
- Temporary data reached 68,719,410,414 bytes, only 66,322 bytes below the
  configured 64-GiB temporary limit. Two retained temporary objects each
  had a logical size of 34,359,705,207 bytes.

A later read-only investigation traced the first object to ZIP member
extraction. The frozen scanner creates a file-backed script-normalized view;
a full-stream `tr P p` of the first retained object compared equal to the
second. Source behavior, event order, and that complete byte relation
strongly support identifying the second as the normalized view, but the old
process log does not itself name its path. Treat that identity as an
evidence-backed inference rather than a directly logged fact.

### Separate 62f4dd75 experiment

- Source-manifest SHA-256:
  `62f4dd75c1fbe535b4da5d6769d2f27b156462e4fe62348bee3d515d972e52d9`.
- The separate exact-root detection leg exited 1 and recorded the expected
  `PcreZipTail32G.UNOFFICIAL` alert at offset 34,359,738,091. Peak
  process-tree and PCRE RSS were 31,970,388 KiB; post-PCRE RSS was
  54,768 KiB. The report's status text conflicted with its detection verdict
  and alert, so the status text is not a clean-scan result.
- Its continuation was safety-stopped before a complete scan report when
  the 48-GiB container approached its limit. The cgroup was largely charged
  to file cache. Its 68,719,410,414-byte temporary peak likewise left just
  66,322 bytes under the 64-GiB temporary limit. The partial continuation is
  not a qualification pass, and a phase-complete sidecar is insufficient
  when the scanner was terminated and its final report is absent.

## E1513158 full-content custody

The retained extraction and normalized objects were each independently
hashed on Sonic1 and their full streams were also verified from a compressed
custody archive on 2026-10-17:

| Object | SHA-256 |
| --- | --- |
| Extracted member `clamav-908fa1d98ed75f027702d3e3a9af11bc.tmp` | `7d7beeb1bac960b08988bfccc644f1a20ea110bc247528bd6b89ce75b36a7b96` |
| Normalized view `clamav-270ce67c8c6d1911858d2d9308de55e7.tmp` | `714ccce1eac2f90b7aa7a4c1b51066ff115817baef6a7a706653059ff158b1ae` |

The custody tarball contains both complete originals with their sizes and
metadata. It is 66,690,461 compressed bytes and has SHA-256
`6d0f70446ed278058453ec863205e7ad3ff4a18757d768940b2eae7bf705d22b`.
Copies are retained on Sonic1 and in the local qualification evidence
collection; these backups are not stored in GitHub by this commit. The compact
raw diagnostic archive has SHA-256
`7b4fb1d3b4c41ec00d456cbcef41c46f24250f919cd79fc0ea9505102f058542`.
Retain these archives, source identities, diagnostic logs, and any recent
qualification evidence.

The principal lesson is that a small process-RSS sample did not prevent
large file-backed temporary objects and their cache charges from driving the
cgroup toward its memory cap. For stored ZIP members, reusing a checked view
of already-resident archive backing can avoid a complete extraction copy, but
script normalization, all other representations and their lifetimes, and
complete-scan coverage still require explicit accounting and tests.
