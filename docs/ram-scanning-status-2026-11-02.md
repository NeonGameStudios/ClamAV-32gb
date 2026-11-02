# RAM scanning qualification status — 2026-11-02

Status: **in progress; full 32 GiB qualification is not complete**. This is a progress record, not a release or a claim that the current candidate has passed every goal.

## What has been demonstrated

- Earlier candidate: scoped Release tests passed for a clean stored ZIP and a late-positive stored ZIP at the exact 32 GiB size. A full-size clean test also passed with C/C++ ASan and UBSan. Rust was not sanitizer-instrumented. These results do not establish continuous residency or an exact physical-memory peak.
- A prior full-size sanitizer late-positive scan reached its expected marker at byte offset 34,359,738,046 but timed out after 6,000 seconds before the scan report and cleanup. It is not a pass. Timeout evidence on Sonic1: `/tmp/clamav-qualification-disk-lv-v1/service-native-asan-stored32-positive-20261102-v3-timeout-evidence.tar.xz`; SHA-256 `1b9b5b7766c433e5442987d92f51befbd7054be1b48333f016d10d883a525c7b`.
- Investigation identified repeated normalized-view hashing as a possible source of replay work. An isolated candidate computes the normalized digest as output is indexed and seeds the virtual fmap hash cache after validation. Its Release and C/C++ ASan/UBSan builds passed; Rust remains uninstrumented.
- On a guarded 64 MiB ASCII late-positive fixture, the candidate matched the baseline normalized digest and false-positive log, while requested replay fell from 128 MiB to 64 MiB. A matching false-positive signature suppressed the known detection; a wrong digest preserved it. The sanitizer build passed the same scoped test.

## Earlier 32 GiB test (historical snapshot)

The current candidate's full-size sanitizer late-positive attempt uses a stored archive view rather than materializing the member. Before handoff, all input pages were observed resident; the view reported zero materialized member bytes and a 10 MiB index covering the member. The cached normalized SHA-256 `aefedaf37864ee7a3d120869e6ead4cf2b586c303270be9bc57206561713cf1d` matched the earlier full-size baseline.

At the time of the earlier update, Sonic1's watchdog, sampler and observer services for attempt v3 were still active. No final scan verdict or completed qualification is asserted here. Previous v1 and v2 attempts were stopped by the conservative host-memory watchdog during staging and after index construction respectively, with no swap or OOM recorded; their evidence was retained.

## Candidate and next qualification

The isolated candidate patch is at `ram-stored-view-candidate-20261031-v1/virtual-replay-ledger-layout-20261102-v1/virtual-index-digest-candidate.patch` in the working handoff area; this status commit does not include or ship that patch. Candidate `scanners.c` SHA-256: `25ec34bed7408f8842adfd89b2fd0dd1b5a14139abd356eb8b3d7468476bf2b1`. Its baseline SHA-256: `4871a3dd5b51a6d6a3c771b232212f5d8c8116507b63b1dfa6b1f75140b7b2b0`. Detailed test and evidence notes are in the working handoff area's `virtual-replay-ledger-layout-20261102-v1/SANITIZER-BUILD.md`.

Review the v3 final verdict and preserved diagnostics before drawing conclusions, then continue exact-source qualification against the full requirements: a 55 GiB physical ceiling, 32 GiB whole-workload RSS, 40 GiB PCRE limit, strict less-than-12 GiB post-PCRE limit, and full residency before readback and scanning. Validate the intended compressed/stored archive coverage and limitations explicitly. Keep tested R27 and prior evidence intact; R28 remains unqualified until its required guards, builds and scoped tests pass.


## Later update — exact-size positive and remaining proof

A subsequent, separately pinned exact 32-GiB Stored ZIP positive scan completed on Sonic1 using the combined Rust/C/C++ sanitizer scanner. The scanner returned the expected `Service.Normalize32Late.UNOFFICIAL` detection and reported `DETECTION_TERMINATED`, 34,359,738,368 input bytes, zero temporary bytes, zero skipped operations, and zero required cleanup failures. The captured stderr contained no ASan, UBSan, or LeakSanitizer error markers. This is a scoped detection result, not complete RAM-mode qualification.

The initial and two terminal observations recorded all 8,388,608 input pages resident with the same backing device/inode. Those endpoint observations do **not** establish continuous residency; the receipt is producer-generated and has not been independently authenticated. Sampled maximum process RSS sum was 1,312,911,360 bytes and sampled cgroup charge was 35,648,622,592 bytes, with no recorded cgroup limit or OOM events. Sampling can miss processes and short peaks, so these numbers do not prove the whole-workload RSS, physical-memory peak, or phase-specific limits. Cgroup charge and process RSS are different measures.

The 36-file suite and journals were preserved on Sonic1 and in a locally verified archive `service-receipt-stored32-20261102-evidence-v1.tar.gz`, SHA-256 `8e5253e914c8827746eeae8e61f7d37a7bc6d7a38281ed088272192930f0d8a3`. The archive and each manifest entry were verified. It remains in the working evidence area and is not included in this status commit.

Work toward complete accounting includes bounded ptrace controls and a disabled scanner tracing candidate. Thread lifecycle accounting and LeakSanitizer compatibility under tracing remain unresolved; these controls do not retroactively qualify the full-size scan. Six synthetic tmpfs-admission controls passed on Sonic1. A first real-mount control failed with a Python import error before the gate ran; its cause is not yet established, and its stopped container remains pending locally verified diagnostic preservation and scoped cleanup. No real-mount pass is claimed.

Next work is to preserve those diagnostics and clean up only the verified idle test container, resolve the import failure and validate the actual tmpfs gate, then establish independent residency and complete resource evidence. Finish exact-source release and sanitizer qualification, exact-size raw and Stored coverage, multiple/nested member cases, boundary and fail-closed tests, and the remaining detector and cleanup coverage. Respect the existing 55-GiB host ceiling and RSS/PCRE phase limits. The Stored-view result does not demonstrate equivalent treatment of deflated ZIP members. R27 and prior evidence remain preserved; R28 and the overall goal remain unqualified.
