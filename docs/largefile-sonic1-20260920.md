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

## C ASan/UBSan qualification slice

Sonic1 produced a separate RelWithDebInfo build with GCC
`-fsanitize=address,undefined -fno-omit-frame-pointer` in the native compile
and link graph, preserving the Release feature set. The tracked sanitizer
CTest run excluding only `largefile_library_exact_32g` completed `31/31`
tests successfully in `396.82 sec`; no AddressSanitizer, UndefinedBehaviorSanitizer,
or runtime-error diagnostics were reported.

- Sanitizer `clamscan` SHA-256:
  `730b54206d3534c16c4edbd79637f3294cc0e4c73c455a705969aa76212db920`.
- CMake cache SHA-256:
  `3c648d81b4f2a29880faed802946452065185ae96c71a5a65ec8c41426be42b2`.
- Compile-commands SHA-256:
  `ad9577537148b36eed4def7bd46b1ef75d82f812779d3d4f5410f1da43abfba4`.
- Source manifest SHA-256:
  `1467bb29c64d76457408cecdefbc1ff9cb84aed64513a58eb76f00a919f16976`.

Rust unit tests passed within this C-sanitized run, but the Rust artifacts
were not address-instrumented: Sonic1 has only stable `1.97`/`stable` Rust
toolchains, and `rustc -Zsanitizer=address` fails because `-Z` requires
nightly. Required Rust sanitizer qualification therefore remains open.

## Exact-size PCRE resource capture

Sonic1 also completed a current-source-bound PCRE positive-control scan over
an exactly 32-GiB logical sparse file. The scan returned
`DETECTION_TERMINATED` with the expected `PcreTail.UNOFFICIAL` alert after
reading `32.00 GiB`; the report recorded equal
`root_size=logical_bytes=contiguous_bytes=34,359,738,368` values and
`matcher_bytes=34,368,129,024`.

The independent process-tree recorder retained 1,538 samples with RSS
`33,636,728 KiB`, PSS `33,634,545 KiB`, VAS `33,691,832 KiB`, zero swap,
zero temporary bytes, zero OOM events/kills, a PCRE RSS peak of
`33,636,728 KiB`, and a post-PCRE RSS peak of `82,296 KiB`. The post-PCRE
acknowledgement was held until an independent sample observed RSS below the
12-GiB budget; high transitional samples remained in the PCRE peak.

This is useful resource-bound evidence, but it is sparse rather than fully
materialized and the positive detection terminates before a legitimate deep
parse phase. It therefore does not promote `matcher:pcre` or clear the
materialized-input, deep-parse, production-CVD/service, sanitizer, fanotify,
or final release gates. Receipt:
`docs/largefile-task-receipts/R13-sonic1-exact-size-pcre-resource-2026-09-20.md`.
