# Large-File Phase 0 Baseline

Date: 2026-08-10

## Source and host

- Source: official `clamav-1.5.3` archive from Cisco-Talos.
- Target: 64-bit Linux/x86-64, with a 32 GiB maximum input target.
- Current audit host: Darwin ARM64.
- The audit host is macOS ARM64; Linux validation was run in an isolated
  64-bit ARM64 Debian container because the host toolchain was not suitable.
- No host software was installed. Build dependencies and the Rust toolchain
  used for validation were confined to Docker containers.

The source is now configured, compiled, and tested in Linux. The result is a
source-hardening candidate, not yet an exact-boundary certification on the
dedicated 64 GiB Ubuntu x86-64 host.

## Generated artifacts

- `docs/large-file-support.md`: specification, memory budget, workstreams, and
  acceptance criteria.
- `docs/largefile-inventory.tsv`: regenerated inventory of 29,646 classified
  source entries. A source line may appear in more than one classification;
  the current snapshot has SHA-256
  `26aa848a5d502cd81e78261e2c450fbf0b4bd3c436b42b26fdc17339966bf20f`.
- `tools/largefile_inventory.sh`: repeatable inventory generator.
- `tools/largefile_boundary_corpus.sh`: sparse boundary-fixture generator,
  including a 32 GiB edge case.
- `tools/largefile_poc.sh`: repeatable scan, offset-check, and resource
  measurement harness.
- `tools/largefile_runtime_gate.sh`: fail-closed Linux/x86-64 release runner
  for exact-boundary, policy, sanitizer, and concurrency evidence. Its output
  directory must be outside the source tree.
- `tools/largefile_runtime_evidence_check.sh`: independent artifact verifier
  for the exact result rows, policy rejection, cancellation, sanitizer status,
  scanner identity, and requested concurrency levels.
- `rust-toolchain.toml`: Cargo/Rust 1.97 release-line pin.

The inventory currently reports:

| Classification | Sites |
|---|---:|
| Native-width integer | 10,219 |
| Offset/size arithmetic | 11,312 |
| Fixed-width integer | 5,213 |
| Format-width specifier | 2,423 |
| Boundary constant | 218 |
| Quantity parser | 103 |
| Narrowing cast | 61 |
| Large-file option | 97 |

These are review candidates, not automatic conversions. The classification
is intentionally over-inclusive so format-defined fields can be separated
from runtime coordinates during the audit.

## Confirmed high-priority sites in the initial snapshot

The following entries record the pre-change inventory and are retained for
audit history. The current state and fixes are summarized below in “Cargo 1.97
and 32-bit audit update.”

- `common/optparser.c:487`: `MaxScanSize` already uses `CLOPT_TYPE_SIZE64`.
- `common/optparser.c:489`: `MaxFileSize` still uses `CLOPT_TYPE_SIZE`.
- `common/optparser.c:516`: `PCREMaxFileSize` still uses `CLOPT_TYPE_SIZE`.
- `libclamav/others.c:677-688`: `MaxFileSize` is clamped near `INT_MAX`.
- `libclamav/matcher.c:99-102`: matcher offset is `uint32_t`.
- `libclamav/matcher.c:263`: buffer length and offset are `uint32_t`.
- `libclamav/matcher-ac.h:51,170`: runtime match offsets and scan API use
  32-bit values.
- `libclamav/matcher-bm.h:52`: BM scan length and offset use 32-bit values.
- `libclamav/matcher-pcre.h:60,73`: PCRE offset ranges and scan length use
  32-bit values.
- `libclamav/matcher-hash.h:54-59`: exact-size hash APIs use `uint32_t`.
- `clamd/scanner.h:52,68`: legacy scan counters use `unsigned long`.
- `libclamav/execs.h:78-84`: executable metadata contains an offset that
  requires semantic classification.
- `CMakeLists.txt:768-769` and `cmake/CheckFileOffsetBits.cmake`: the build
  already checks whether `_FILE_OFFSET_BITS=64` is needed.

## Current validation

- The complete tree builds successfully in a 900 MiB Linux ARM64 Docker
  environment using serial C and Rust jobs.
- The complete configured CTest suite passes 10/10, including `libclamav`,
  Rust FFI/layout, `clamscan`, `clamd`, `freshclam`, `sigtool`, milter quota,
  source guards, and the large-file harness/evidence controls.
- 2 GiB−1 through 16 GiB sparse cases were detected with marker positions
  independently verified.
- The 32 GiB edge scan was killed by the available Linux/Docker memory
  environment at about 3.56 GiB RSS; this is recorded as a resource-limit
  failure, not a clean result.
- Focused valid and malformed regressions pass for the hardened matcher,
  paging, archive, document, PE trust, limit, timeout, and DMG paths.

## Cargo 1.97 and 32-bit audit update

The repository now selects Cargo/Rust 1.97 through `rust-toolchain.toml` and
rejects older Cargo versions from CMake configuration. This is required because
the checked-in `Cargo.lock` uses format version 4, which the prior Cargo 1.65
environment could not parse. The Rust suite was verified separately with Cargo
1.97 and passed 60/60; no new repository binary was created during this source
and documentation update.

The remaining 32-bit-limited runtime paths addressed in this slice are:

- `MaxEmbeddedPE`, normalization limits, `OnAccessMaxFileSize`, and
  `StreamMaxLength` now accept 64-bit size-policy values. Individual consumers
  may still impose narrower parser or memory limits.
- The checked-in Rust FFI bindings were synchronized with the widened C
  matcher, PCRE, hash-table, and logical-match structures.
- INSTREAM connection state and the clamdscan sender now carry 64-bit
  cumulative quotas. Individual wire chunks remain 32-bit because
  that is part of the INSTREAM protocol.
- `fmap_readn()` no longer converts a successful `size_t` read into an error
  merely because it exceeds `INT_MAX`.
- The PCRE2 wrapper and result offsets use `size_t`, so full-map matching no
  longer has an artificial 4 GiB type guard. `PCREMaxFileSize` still protects
  against unsafe contiguous allocations.
- CAB/CHM offsets are checked for representability by `off_t` rather than
  rejected at 2 GiB, and their default extraction budget no longer falls back
  to `UINT32_MAX`.
- Calculated AC/BM/PCRE relative-offset caches are 64-bit and BM offset mode
  is no longer rejected solely because the file position exceeds 4 GiB.
- `PCREMaxFileSize` is parsed as a 64-bit option, and Microsoft archive
  partial-write reporting now respects the remaining extraction budget.
- Native logical/YARA/macro/byte-compare offsets now use 64-bit runtime storage.
  Bytecode-dependent logical signatures still pass through a checked bridge to
  the frozen 32-bit bytecode globals; version-info remains a 32-bit PE RVA
  hashset boundary.
- ZIP catalogue/raw-header coordinates and OOXML search offsets now use
  native-width coordinates, bounded readers, and checked ZIP64 placement.
  Runtime payload proof above 4 GiB remains part of the high-memory gate.
- OLE2 block byte offsets now use checked 64-bit arithmetic instead of the
  previous `INT32_MAX` map rejection. CFB sector IDs and VBA format lengths
  remain fixed-width; the legacy in-memory VBA matcher still returns
  `CL_EFORMAT` for an unrepresentable buffer.
- XAR TOC dimensions, UDF allocation offsets, HFS+ block-to-byte conversions,
  and DMG fork/stripe coordinates use checked native-width arithmetic.
  XAR and DMG compressed input is streamed; their legacy metadata parsers have
  explicit 64 MiB fail-visible caps.
- Embedded PE analysis now checks its 32-bit executable metadata offset and
  marks embedded objects above 4 GiB incomplete instead of truncating the
  offset or allowing a clean result.
- Hash database size parsing and exact-size lookup accept 64-bit sizes while
  preserving the existing 32-bit hash table for legacy entries.
- The POC harness validates manifest file sizes and distinguishes an engine
  offset from the independent marker-location check.

Still-open release gates are listed in `large-file-support.md`: intentional
contiguous-parser and legacy-ABI caps, broader real-world container fixtures,
sanitizer coverage, exact 32 GiB execution, Linux x86-64 deployment evidence,
daemon/milter integration, and measured concurrency. Frozen or unsupported
paths produce an explicit incomplete non-clean result rather than an
unqualified clean result.

## Next gate

Run the release gate on the dedicated 64 GiB Ubuntu x86-64 host with one
worker, then the measured 1/2/4-worker matrix and ASan/UBSan build. Complete
exact 32 GiB head/edge detection, 32 GiB+1 rejection, cancellation,
INSTREAM/FILDES, milter, malformed-container, and evidence-attestation checks
before any production designation or upstream proposal.
