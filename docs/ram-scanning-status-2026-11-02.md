# Sonic1 RAM scanning: progress update, 2026-11-02

Status: **work in progress; the 32-GiB goal is not qualified**. This is a status and evidence index, not a release or a claim that the experimental scanner is production ready.

## Furthest full-size result

On Sonic1, the separately frozen revision9 candidate scanned an exact 32-GiB RAM-resident Stored ZIP in clean and late-detection controls. In both runs all 8,388,608 input pages were observed resident before initial readback and at both native terminal observations. The late-positive member's expected signature was found in its final 28 bytes. The positive returned DETECTION_TERMINATED, so it is not a complete-clean result. Its report recorded one created and released resident archive view, zero complete-member materialization, zero temporary bytes, zero skipped operations and zero required cleanup failures.

The clean and positive conservative whole-workload high-water bounds were 505,905,152 and 509,755,392 bytes respectively; sampled cgroup peaks were 38,277,021,696 and 38,304,997,376 bytes. These are different measurements: the cgroup figures include memory charged outside process RSS, including the resident backing. Zero swap, OOM and max events were recorded. These results establish the exercised capacity, **not continuous residency or overall qualification**. The input was a ZIP using the Stored method; this does not establish support for arbitrary compressed or deflated members.

The complete full-size diagnostic archives have been preserved on Sonic1 and transferred locally with manifest verification. Clean archive SHA-256: `8140d77bf4b0a1ebfe4e67f6ffdd85d334db0234f954bda9a1b9a50a420e734b`; positive archive SHA-256: `0a5c41f908f484cb91abbb52f262d0ecee6928ce6b9754720f5c5370548a1414`. These archives are not included in this commit.

## Subsequent findings

- Small actual-scanner Release controls exercised admission refusals, sealed backing, allocation-domain binding, cancellation, and busy view/pager lifetimes. They do not replace the remaining full-size matrix.
- A full scanner built with combined Rust/C/C++ sanitizers found the expected late signature in a 64-MiB ordinary-filesystem Stored ZIP control. LeakSanitizer was active. This small filesystem case does not prove RAM-mode residency or full-size sanitizer acceptance.
- Continuous ptrace interferes with LeakSanitizer. An experimental observer that stops a known sibling while an exec notification is pending allowed the actual sanitizer scanner to run, but complete task discovery, shared-memory clones, exec-boundary memory accounting and failure handling are not established.
- A host scheduler-fork tracepoint observed the scanner's child in a gated one-CPU test using an atomic perf-ring helper. Correlation with the LeakSanitizer helper is an inference: live host/container PID mapping was not independently captured.
- An intentional ring-overflow control demonstrated that a single final drain can miss a delayed loss report: 65 missing events were reported only after a later sentinel event. A separate sequential control observed clean birth and sentinel events on all 12 then-online CPUs, and detected the intentional 65-event loss case. These experiments do not prove a production-safe, loss-free observer.

Experimental observer evidence is locally retained with verified manifests, including the atomic actual-scanner control archive SHA-256 `41673cbaab91c7447011776882f41bf7886b35fac0b8ec7ac83d3d9b5abd29e2`, overflow archive `3431b1008096e289e3d96f96d1b5395e645ff089609ca68f8f8148f74660e482`, and per-CPU control archive `65410a156031327d11dd8947eb7678cfe314f9e28584e16a9615ffccdba876a2`. The archives themselves are not published here.

## Remaining work and constraints

Qualify the full-residency continuity argument and complete process-tree accounting, including task generations, shared-memory descendants, exec transitions, loss detection and observer failure. Complete final-policy exact-size raw and Stored cases, multiple and nested Stored members, broader detector coverage, interruption/cleanup cases, and full-scanner Release and sanitizer evidence. The exact sequence must be driven by fresh Sonic1 workload preflight and preserve prior evidence.

The goal retains the 55-GiB physical ceiling, 32-GiB whole-workload RSS limit, 40-GiB PCRE limit, strict under-12-GiB post-PCRE limit and zero swap. Do not count demand paging or a warmed disk cache as full residency, and do not weaken the limits or substitute disk staging for RAM residency.

Earlier historical PCRE custody findings were published separately in commit `8d72d3fbc60d8ac7a4c83fbe7f073169807d7bcd` on branch `codex/sonic1-pcre-historical-custody-20261101`. This status update does not publish the candidate source or the local evidence archives.
