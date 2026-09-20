# Sonic1 large-file qualification slice — 2026-09-20

## Scope

This note records one current-source qualification slice from the active
32-GiB roadmap goal. It is evidence for the exact logical boundary in the
library API, not a release certificate and not a claim that all ingress or
parser capabilities are qualified.

## Runner and build identity

- Runner: Sonic1, Linux x86-64.
- Current source candidate: local commit `7fd3a2dc` (`Initialize EGG fixture contiguous budget`).
- Container image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Release qualification binary SHA-256: `d673f28830de0fca93efedc3085221e7f19639663229239829fce0f75deefad3`.
- Source-manifest SHA-256: `bb90de9dc0a7f4c4648efce80c60003d995680d035d9022134c94417e591b9f4`.
- CMake options: `CMAKE_BUILD_TYPE=Release`,
  `ENABLE_LARGE_FILE_DEFAULTS=ON`,
  `ENABLE_LARGE_FILE_QUALIFICATION_TEST=ON`.

The host preflight reported 65,234,456 KiB total memory and 62,290,356 KiB
available memory, with no finite container memory limit. It also reported
29,534,956 KiB available in the container filesystem. Host inspection found
about 30.2 GB free disk-backed space and an 8 GiB swap device with about
0.9 GiB in use. Consequently, this runner is suitable for the sparse logical
probe below, but it does not currently satisfy the roadmap's no-swap and
68-GiB free disk-backed materialized-release prerequisites.

## Exact sparse boundary result

Command:

```text
ctest --test-dir /tmp/clamav-7f3458c4-release-build \
  -R '^largefile_library_exact_32g$' --output-on-failure -V
```

Result: `1/1` passed, `0` failures, `0` errors, wall time `347.20 sec`.

The test creates a sparse logical file of exactly 32 GiB, writes a unique
marker at the final 64-byte region, and verifies detection through the
current library's file, descriptor, and fmap scan paths. The test completed
with the expected exact-tail detection and configured 32-GiB policy values.

## Qualification boundary

This result is a successful current-source sparse boundary probe. It does not
promote any row in `docs/largefile-capabilities.tsv` to authoritative release
evidence because it does not prove fully materialized disk-backed input,
32-GiB-plus-one rejection, parser/deep-inspection completion, daemon or
client ingress parity, sanitizer behavior, fanotify prevention, PCRE resource
limits, or the production-CVD canary. The release-readiness gate therefore
remains blocked until those independent evidence requirements are satisfied.

## Regression suite result

With the exact sparse test excluded, the remaining current-source CTest
regression suite passed `31/31` in `211.29 sec`. This included the library,
Rust, clamscan, clamd, freshclam, sigtool, milter, on-access, source-guard,
and release-control tests.

A combined 32-test CTest invocation was attempted with the exact test enabled,
but the MCP Docker job ended with exit `137` as test 8 started and stopped the
container. Sonic1 still reported about 63.97 GiB available memory afterward,
and Docker reported `OOMKilled=false`; therefore that invocation is recorded
as a runner/wrapper failure, not as a ClamAV test result. The separately
tracked exact test above is the authoritative exact-boundary result for this
slice.

## CLI boundary results

Using the same Release binary with an explicitly bound checked-in CVD
certificate directory and a deterministic local NDB:

- Exact sparse 32-GiB file with a marker at offset 4096 returned exit `1` and
  `LargeFile.POC.32g-head.UNOFFICIAL FOUND`.
- The matching exact sparse 32-GiB unknown-length stdin stream returned exit
  `1` and `stdin: LargeFile.POC.32g-head.UNOFFICIAL FOUND`.
- Sparse 32-GiB-plus-one file input returned exit `1` with
  `Heuristics.Limits.Exceeded.MaxFileSize FOUND` and a fail-visible incomplete
  warning.
- The matching 32-GiB-plus-one unknown-length stdin stream returned exit `1`
  with `stdin: Heuristics.Limits.Exceeded.MaxFileSize FOUND` and no clean
  result.

These are boundary-policy and ingress probes against sparse fixtures. They do
not replace the roadmap's fully materialized exact-edge, deep-parser, service,
sanitizer, fanotify, or production-CVD evidence.

## Development service matrix

The current-source development service producer was corrected to bind its
structured reports to the contract's 64-GiB logical scan budget while keeping
the small development fixtures and bounded temporary/matcher limits. Sonic1
then completed all 36 bounded R04 records: six direct clamd report commands
and six clamdscan client modes across clean, detection, and limit outcomes.

- Capture exit: `0`; producer output: `development service capture wrote 36 R04 records`.
- Source-bound producer SHA-256: `22c4739fd71d3f054a2fe244a97333834f78c8bf94a574b83e8a6e656a03f8c3`.
- Acceptance-record SHA-256: `9894540371613f42df2bfd9eae9d7a0bd1b8482b417b816eb24cedeb0a780e67`.
- The capture validator passed the capability/case bindings, exact outcomes,
  detection offsets, health, cleanup, and development resource envelope.

This is still development evidence: it does not qualify materialized 32-GiB
service inputs, sanitizer parity, production CVDs, fanotify, PCRE resource
phases, or final release readiness.
