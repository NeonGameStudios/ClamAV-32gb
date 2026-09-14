# Task receipt: R10/R11 current-source Release service capture after rebind

Task IDs / parent milestones: `R10`, `R11` / `R04`, `R03`.

The source-aligned ARM64 Release `clamd` and `clamdscan` build at
`/tmp/clamav-release-current-20260913` generated a fresh development service
bundle at `/tmp/clamav-r04-service-release-current-20260913e`. The run used
the repository signing-certificate directory
`/src/unit_tests/input/signing/verify` and bound the current source manifest
SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.

Retained identity hashes:

- build identity: `f3dd82fe6b0a6bb9d0fb01be094b53b61fa3cda51b3aab18a944fa9bf3f1f3ad`;
- CMake cache: `1f125879914959b31775438b6dbd865a1bf45e219c587c92ecd424df1d5b45e9`;
- acceptance TSV: `3f3ed9ce694e1f940f33276582e3d4a4d46b3872466bc12688c99137d3b7dd1f`.

The live capture exited 0 and wrote 36 records covering all six structured
`clamd` report commands and all six `clamdscan` client modes across clean,
exact-detection, and configured-limit outcomes: 12 `COMPLETE`, 12
`DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE`. All records retained
passing daemon health and cleanup lifecycle state. The standalone verifier
also passed: `large-file acceptance record schema passed (36 records)`.

This is small-fixture ARM64 development evidence only. It does not prove
exact 32-GiB/materialized service behavior, certified Linux x86-64 resource
limits, production CVD coverage, privileged fanotify, Sonic1, independent
format-8, or final release qualification. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
