# RAM scanning qualification status — 2026-11-02

Status: **in progress; full 32 GiB qualification is not complete**. This is a progress record, not a release or a claim that the current candidate has passed every goal.

## What has been demonstrated

- Earlier candidate: scoped Release tests passed for a clean stored ZIP and a late-positive stored ZIP at the exact 32 GiB size. A full-size clean test also passed with C/C++ ASan and UBSan. Rust was not sanitizer-instrumented. These results do not establish continuous residency or an exact physical-memory peak.
- A prior full-size sanitizer late-positive scan reached its expected marker at byte offset 34,359,738,046 but timed out after 6,000 seconds before the scan report and cleanup. It is not a pass. Timeout evidence on Sonic1: `/tmp/clamav-qualification-disk-lv-v1/service-native-asan-stored32-positive-20261102-v3-timeout-evidence.tar.xz`; SHA-256 `1b9b5b7766c433e5442987d92f51befbd7054be1b48333f016d10d883a525c7b`.
- Investigation identified repeated normalized-view hashing as a possible source of replay work. An isolated candidate computes the normalized digest as output is indexed and seeds the virtual fmap hash cache after validation. Its Release and C/C++ ASan/UBSan builds passed; Rust remains uninstrumented.
- On a guarded 64 MiB ASCII late-positive fixture, the candidate matched the baseline normalized digest and false-positive log, while requested replay fell from 128 MiB to 64 MiB. A matching false-positive signature suppressed the known detection; a wrong digest preserved it. The sanitizer build passed the same scoped test.

## Current 32 GiB test

The current candidate's full-size sanitizer late-positive attempt uses a stored archive view rather than materializing the member. Before handoff, all input pages were observed resident; the view reported zero materialized member bytes and a 10 MiB index covering the member. The cached normalized SHA-256 `aefedaf37864ee7a3d120869e6ead4cf2b586c303270be9bc57206561713cf1d` matched the earlier full-size baseline.

As of this update, Sonic1's watchdog, sampler and observer services for attempt v3 were still active. No final scan verdict or completed qualification is asserted here. Previous v1 and v2 attempts were stopped by the conservative host-memory watchdog during staging and after index construction respectively, with no swap or OOM recorded; their evidence was retained.

## Candidate and next qualification

The isolated candidate patch is at `ram-stored-view-candidate-20261031-v1/virtual-replay-ledger-layout-20261102-v1/virtual-index-digest-candidate.patch` in the working handoff area; this status commit does not include or ship that patch. Candidate `scanners.c` SHA-256: `25ec34bed7408f8842adfd89b2fd0dd1b5a14139abd356eb8b3d7468476bf2b1`. Its baseline SHA-256: `4871a3dd5b51a6d6a3c771b232212f5d8c8116507b63b1dfa6b1f75140b7b2b0`. Detailed test and evidence notes are in the working handoff area's `virtual-replay-ledger-layout-20261102-v1/SANITIZER-BUILD.md`.

Review the v3 final verdict and preserved diagnostics before drawing conclusions, then continue exact-source qualification against the full requirements: a 55 GiB physical ceiling, 32 GiB whole-workload RSS, 40 GiB PCRE limit, strict less-than-12 GiB post-PCRE limit, and full residency before readback and scanning. Validate the intended compressed/stored archive coverage and limitations explicitly. Keep tested R27 and prior evidence intact; R28 remains unqualified until its required guards, builds and scoped tests pass.
