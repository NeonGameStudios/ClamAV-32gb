# RAM-scanning progress — 2026-11-07

This is a progress record, not a qualification claim.

## Engine-first bridge and flow

The separate v32-v2b Release build on Sonic1 succeeded under the approved build policy. Its artifact manifest reports that `rrp_observe_owned_file` is exported. The bridge SHA-256 is `1c62d09658ee0bfd285442d960bd777fb0db934c5da9cbd369f0fd6d41c0dcb4`; the v32-v2b scanner SHA-256 is `29c28145087d9f877aa4a02486f3fbd4597359c6bf70cd33c5db7b18fc4d7ecd`.

The later v33-v6-r3 bounded run passed its seven small controls and completed the lease → engine load → budget/admission → stage/seal → scan → cleanup flow. It scanned a 157-byte ZIP_STORED positive fixture and produced the expected synthetic detection. Cleanup passed, neither container was OOM-killed, and the slice was inactive afterward. Its bridge hash matches the repaired v32-v2b bridge. Its scanner hash (`a9e76660753af5180459d166dd5e31025794c9136dfc590c1e3c63056b99ee16`) differs from the v32-v2b scanner hash, so this is evidence for the later v33 derivative with the repaired bridge, not an exact-v32-scanner end-to-end run.

## Stored-ZIP size controls

R31 (928 MiB) and R32 (960 MiB) passed as bounded synthetic ZIP_STORED positive controls using the frozen v38 R21 scanner/build. Both used the 2-GiB test cap, zero swap, and the integrated engine-first flow. The expected late `PcreZipTail32G.UNOFFICIAL` detection was reported as `CL_TYPE_ZIP`; both runs recorded zero materialized bytes, skipped operations, and required cleanup failures.

R32 reached the configured 1-GiB scanner-tmpfs floor exactly, with no capacity beyond that floor. Maximum sampled workload current was 2,045,755,392 bytes, about 97 MiB below the 2-GiB cap. Do not advance the size ladder under these unchanged limits. These watchdog values are sampled observations, not continuous peak guarantees.

## Remaining qualification

Exact-32-GiB raw and ZIP_STORED scans, realistic production-database coverage, continuous residency evidence, sanitizer/final-release coverage, and the 48-GiB recommended / 40-GiB minimum system profiles remain unqualified. The bounded controls above do not establish those targets.
