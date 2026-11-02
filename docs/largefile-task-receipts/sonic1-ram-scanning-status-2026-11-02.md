# Sonic1 RAM-resident 32-GiB scanning status — 2026-11-02

Status: **work in progress; overall qualification has not passed**. This is a
status receipt, not a publication of the candidate source or complete raw
evidence. Test results apply only to the identified runs and configurations.

## Objective

Scan exact 32-GiB inputs fully resident in RAM, including supported ZIP Stored
members as views of the same resident backing rather than full extracted
copies. Preserve complete-scan and fail-closed behavior. The existing limits
remain: under 32 GiB whole-workload process RSS, 40 GiB for the PCRE phase,
under 12 GiB after PCRE, and 55 GiB physical host memory. Initial all-page
residency, appropriate lifetime/continuity evidence, and cleanup are required.

## Results so far

- Release candidate runs completed an exact-32-GiB single-Stored-member clean
  scan and a separate late-detection scan. Both observed all 8,388,608 input
  pages resident at admission and terminal checkpoints; these are scoped
  capacity and functional results, not continuous-residency or overall
  qualification.
- An exact-32-GiB clean Stored-ZIP C/C++ ASan/UBSan scanner run completed
  with zero materialized member bytes, temporary bytes, skipped operations,
  or cleanup failures. Evidence archive SHA-256:
  `a8ad264d8cd22a9dfed98892a7d851d2151e764fb79dcf9122464ccc194e3ee0`.
- A separate exact-32-GiB late-positive C/C++ ASan/UBSan run of a candidate
  digest-caching optimization detected the expected signature at member
  offset 34,359,738,046. It returned detection status after 5,502.529
  seconds, with zero reported temporary bytes, skips, or cleanup failures.
  The Stored view reported zero materialized bytes and all input pages were
  resident at both final checkpoints. Rust was not sanitizer-instrumented.
  This synthetic, detection-terminated case is not a complete clean scan or
  overall qualification.
- For that late-positive run, the sampled maximum host nonfree was
  50,924,040,192 bytes and sampled process RSS sum 1,304,567,808 bytes.
  These are samples, not proven instantaneous maxima. Neither establishes
  the required hard physical or whole-workload RSS bound.
- An earlier late-positive sanitizer run found the signature but timed out
  before the final scanner report. It remains a failed/incomplete attempt.
  Subsequent work caches the normalized digest during existing indexing; a
  64-MiB control matched the previous digest and reduced replay, and the
  later full-size run above completed. Additional normalization, false-positive
  and synchronization coverage is still needed.

## Remaining work

1. Establish a complete process-lifetime RSS ledger and a defensible
   all-inclusive physical-memory bound. Periodic process and host samples
   can miss short-lived processes and peaks.
2. Establish and independently review the required residency continuity
   policy and evidence. Endpoint residency observations alone do not prove
   continuous residency.
3. Complete final-policy exact-size raw and supported Stored-ZIP clean and
   late-positive tests, multiple/nested members, exact/oversized boundaries,
   detection families, cancellation, fail-closed behavior, and cleanup.
4. Complete Release and sanitizer coverage, including instrumented Rust,
   PCRE and post-PCRE phase limits, and exact-source build/guard validation.

A non-ptrace Linux taskstats listener is being investigated for exit
accounting. Small controls show compatibility with leak-enabled scanner
startup and ordinary small scans, and demonstrate fail-visible socket
overflow. Exit events alone do not reliably establish process-tree membership,
thread grouping, complete delivery, PID generations, or live endpoint
coverage. Ptrace conflicts with LeakSanitizer in the tested setup. A fresh
64-MiB consumed-RAM diagnostic suite has been staged on Sonic1; it has not
been run as part of this listener integration.

Frozen R17/R27/R118 and prior evidence are retained. The October PCRE
continuation findings and verified custody copies are documented separately in
[the historical custody receipt](sonic1-historical-pcre-custody-2026-11-01.md).
The detailed current working records and evidence remain on the workstation
and Sonic1; this receipt does not claim those artifacts are all in GitHub.

