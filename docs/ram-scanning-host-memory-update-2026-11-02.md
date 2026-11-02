# 32 GiB RAM scanning: host memory qualification update

Status: **in progress; full qualification is not complete**. This update supplements `ram-scanning-status-2026-11-02.md`; earlier statements about work pending describe their historical point in time.

## Scanner progress

On Sonic1, exact-32-GiB raw clean and late-positive scans and Stored-ZIP clean and late-positive scans have completed in scoped tests. Exact-size multiple-member and nested Stored cases also achieved functional clean and late-detection results. The Stored route uses checked views of the resident archive rather than a second complete member backing. A separately pinned combined Rust/C/C++ sanitizer scanner returned the expected normalized late detection on an exact-32-GiB Stored archive; its evidence archive SHA-256 is `8e5253e914c8827746eeae8e61f7d37a7bc6d7a38281ed088272192930f0d8a3`.

The relevant initial and terminal observations reported all 8,388,608 input pages resident. These observations do not independently prove continuous residency. Specific functional results do not substitute for the remaining detector, resource, lifecycle, failure-path and exact-source qualification.

## Current priority: whole-host physical ceiling

The goal requires a 55-GiB physical ceiling, strictly less than 32 GiB whole-workload RSS, a 40-GiB PCRE ceiling, strictly less than 12 GiB post-PCRE, zero swap and full input residency before scanning. The 32-GiB RSS limit is distinct from the physical memory occupied by the 32-GiB resident backing.

Periodic whole-host samples from successful full-size cases were below 55 GiB, but cannot rule out a transient peak between readings. Another earlier run sampled 61.82 GiB of host nonfree memory, including substantial pre-existing reclaimable cache; that observation does not establish the workload's attributable usage. We do not have a sound continuous combined-host peak bound, complete whole-process RSS and phase evidence, or independently authenticated continuous-residency proof. The task remains unqualified.

On the deployed kernel, root cgroup memory statistics and child peaks do not supply the missing whole-host interval bound. Investigation of page-allocation event and BPF tracing approaches found incomplete coverage, callback-suppression and lifecycle concerns. Earlier perf attachment controls did not prove that BPF callbacks were task-private: callbacks ran before the perf task filter. The original evidence remains preserved and its interpretation corrected.

A low-frequency getpid fentry lifecycle control passed, with exact program and link IDs subsequently absent. It does not establish safety, losslessness or coverage for a high-frequency host-wide memory-accounting hook. The proposed high-frequency hook remains disabled and has not been run.

A draft supervisor's handshake, wrong-owner, hung-child, missing-checkpoint and excessive-output controls passed with **mocked** BPF lookups on Sonic1 (job `job_149a34ee13904e0aae6a499458667649`). This is protocol testing only: no BPF was loaded and it is not cleanup or qualification evidence. Review identified that the draft's synchronous object verification could hold a link reference if a kernel query blocks. A separate verifier process can isolate those references from the parent, but a helper stuck in an uninterruptible kernel call could still retain a link; timeout and detachment would remain unknown. The high-frequency observer and supervisor are not approved for actual attachment.

## Next steps and evidence

Establish a defensible, safe way to bound combined whole-host physical memory before further full-size qualification. Continue the independent residency, process-tree and phase accounting, exact-source Release and sanitizer, detection, boundary, fail-closed and cleanup evidence required by the goal. Do not interpret successful Stored method-0 scanning as support for deflated ZIPs.

Detailed local analysis is in `ram-stored-view-candidate-20261031-v1/taskstats-feasibility-20261102-v1/HOST-MEMORY-PEAK-INTERFACES-20261102.md`; draft scripts and test evidence are in the same working handoff area. Those local files and evidence archives are not part of this documentation-only GitHub update. Preserve R27, frozen source and prior evidence.
