# R04 — recompute service fixture identity — 2026-09-29

Scope: capability-specific acceptance-record verification. This is a source
change and bounded local/Sonic1 verifier regression, not a new scanner run or a
qualification promotion.

The R04 verifier previously accepted `service-inputs-before.json` when its
`sha256` string matched the case row, without reading the external service
fixture. A substituted JSON label could therefore satisfy that part of the
record check even if the file at `input` had different bytes. The service
workload verifier has separate checks, but the R04 record verifier itself
must fail closed.

`tools/largefile_acceptance_cases.py` now opens each referenced regular input,
checks its size and recorded allocation/hole metadata, hashes its full bytes,
and checks that the open descriptor and its pathname retain the same file
identity across the read. Nonblocking open prevents a replaced FIFO from
hanging the verifier. The exact-32-GiB-or-larger
path requires materialized allocation and `SEEK_HOLE` at EOF. The final path
component may not be a symlink. Repeated cases for a fixture role share one
full hash verification per verifier call so a service matrix does not rehash
the same 32-GiB input for every command mode.

The service case producer now requires byte-identical
`service-inputs-before.json` and `service-inputs-after.json` before writing
records, and retains both in every mapped case. The independent R04 case
verifier requires those two retained artifacts to match as well. The service
gate already generated and compared both files; this change carries that
post-run identity through to each capability-specific record.

The record verifier also rejects `fixture_role=-` for every case. The R04
contract requires a real fixture identity; the dash formerly bypassed the
retained-fixture check for a non-lifecycle case.

The service-fixture regression now rejects same-size content mutation,
missing input, wrong allocation, a falsely claimed 32-GiB materialized input,
and a symlinked final input. The producer regression uses a real fixture hash
and actual allocated-block count instead of a synthetic 64-hex label. Both
the producer and independent record verifier reject a missing or changed
post-run snapshot. The standalone-record regression rejects the
missing-fixture-role bypass and simulated pathname replacement.

Local commands and outcomes:

- `python3 -B tools/largefile_acceptance_cases_test.py`: 16/16 passed.
- `python3 -B tools/largefile_acceptance_case_producer_test.py`: 11/11 passed.
- `python3 -B tools/largefile_acceptance_resources_test.py`: 7/7 passed.
- `git diff --check`: passed.
- `sh tools/largefile_source_guards.sh`: exited 0; the 604-capability map,
  empty-record fail-closed state, and source guard regression suites passed.

## Sonic1 v10 source-bound verifier run

The deterministic package `/private/tmp/clamav-v10-r04-20260929.tar.gz` was
frozen from the current dirty canonical checkout. Its package SHA-256 is
`d82a3a60cd6c6eccedbbc8001a5925901df184745dabe6bcbc5e0bb6a58e78be`
and size is 17,913,093 bytes. Its content-manifest SHA-256 is
`a8bcd93903525147ababd91633e6764e570136ff4239332cb73c60d3e62a3d6a`.
MCP-SSH durable transfer `transfer_77f0ca552870446faf4b19351359dc2a`
committed by atomic rename to the Sonic1 qualification LV. An independent
container-side SHA-256 matched the package. The archive was extracted at
`/qualification/source-v10-r04-20260929`; the Git-less regenerated manifest
matched the packaged manifest byte-for-byte and had the same SHA-256.

Host/profile: `sonic1` / `sonic1-camera-key`; pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The source-bound remote Python suites passed: R04 cases 16/16, case producer
11/11, and resource binding 7/7. The first full source-guard invocation,
`job_e08ad12c89a2447e85b55e59607718b8`, exited 1 because Docker used its
default working directory; the guard's relative source path did not exist
there. It is a retained invocation error, not a source failure. The corrected
source-root invocation, `job_38d5bf460e7849709ab2ccd6a205cd3a`, exited
0: capability manifest 604 entries, case map 604 capabilities, readiness
regressions and all source guards passed.

Local `largefile_release_readiness.sh --status` still exits 1 as expected:
604 total, 0 qualified, 147 bounded, 443 pending, 14 unsupported and 590
blocked capability rows; `release_readiness=blocked`.

The frozen Sonic1 v9 package predates this verifier edit. Its Release and C
ASan/UBSan exact-32-GiB raw results remain separately documented, but they
do not prove a v10 scanner run. The v10 transfer validates only its packaged
source and Python tools; new coherent binaries and full-size runs remain
required for current-candidate qualification. No service capability or final
readiness state was promoted. No fixture was moved or deleted, software
installed, usage reset used, commit made, push made, or GitHub workflow
triggered.

State: `R04-fixture-identity-verifier-hardened-on-v10-Sonic1-source; v10-scanner-requalification-pending`.
