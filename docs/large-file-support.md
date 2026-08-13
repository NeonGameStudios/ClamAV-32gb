# ClamAV Large-File Support

Status: Phase 3 — source-hardening/build candidate; production acceptance pending

## Target

LargeFile 1.0 targets direct raw scanning of inputs from 0 through 32 GiB and
bounded inspection of audited containers on supported 64-bit x86-64/AMD64 and
AArch64/ARM64 builds. Linux x86-64 is the initial release-certification target;
builds on other accepted 64-bit platforms are compile/test coverage until they
receive their own runtime evidence. The implementation must not silently
truncate file positions, object sizes, scan counters, match positions, hashes,
or parser state.

This is a bounded large-file capability, not an unlimited-resource mode. A
parser or matching subsystem that cannot safely process an object must either
continue with the safe raw scan path and report the limitation, or fail the
scan visibly. It must never produce an unqualified clean result for data it
did not inspect.

## Coordinate and type rules

Use explicit semantic types rather than widening every integer:

- `cli_fileoff_t` / `uint64_t`: absolute positions within the input or a
  containing object.
- `size_t`: host-memory buffer lengths and indexes, after checked conversion
  from a file/object size.
- Fixed-width integers: fields whose width is defined by a file format,
  database format, bytecode ABI, or serialized API.
- Checked helpers: addition, range containment, multiplication, and conversion
  between file coordinates and memory lengths.

The audit must distinguish format-defined 32-bit values from runtime
coordinates. For example, a PE RVA can remain 32-bit while the containing-file
offset used to locate that PE must not be limited to 32 bits.

## Toolchain requirement

The repository pins the Rust toolchain to the Cargo 1.97 release line in
`rust-toolchain.toml`. CMake also enforces Cargo 1.97 or newer so builds that
use a system Cargo fail during configuration with an actionable message.
Cargo 1.65 cannot read the repository's version-4 `Cargo.lock`; Cargo 1.97
compiled and ran the existing Rust suite successfully (60 tests passed in the
native-library test environment).

## Initial baseline findings

The 1.5.3 source has these deliberate or high-priority boundaries:

- `common/optparser.c`: size-policy options must retain 64-bit parsing all the
  way through option storage and engine configuration.
- `libclamav/others.c`: `CL_ENGINE_MAX_FILESIZE` is explicitly clamped near
  `INT_MAX`.
- `libclamav/matcher.c`: raw scan buffer lengths and scan offsets are
  `uint32_t`.
- `libclamav/matcher-ac.h` and matcher APIs: runtime match offsets include
  32-bit fields.
- `libclamav/matcher-hash.h`: exact-size hash lookup and registration use
  `uint32_t` sizes.
- `clamd/scanner.h`: legacy scan counters use `unsigned long`.
- `libclamav/execs.h`: executable metadata includes containing-file offsets
  that must be classified separately from format-defined fields.

These findings are audit inputs, not automatic conversion instructions. The
current implementation has resolved the principal runtime truncation and
fail-open issues called out by the repository audit. The complete configured
normal suite is green in the constrained Linux build; remaining work includes
intentional ABI/parser caps and the high-memory release-gate validation
described below.

## Audit-fix disposition

- BM offset tables use an explicit 64-bit comparator and have a focused
  ordering regression test.
- Milter message accounting uses checked 64-bit totals and sends large input
  in protocol-sized chunks.
- Bytecode/logical, version-info, embedded-PE, and incomplete CAB extraction
  paths mark the scan incomplete and return a non-clean parse result instead
  of silently returning clean.
- ZIP EOCD search is bounded to the legal classic trailer window, ZIP64
  placement is checked separately, and fallback local-header scanning observes
  the scan deadline even on malformed input.
- The POC harness now computes the signature per row, verifies size, status,
  signature, and engine-reported offset, aggregates failures, works with both
  GNU and BSD `time`, and is covered by executable positive/negative scanner
  stubs plus a fail-closed CTest/CI check.
- Size-policy parsing and engine configuration enforce a 32 GiB ceiling, and
  the CMake configuration rejects platforms without 64-bit pointer, size, and
  file-offset types.
- Logical FileSize ranges and calculated matcher offsets now retain 64-bit
  values. Native matcher sentinels are outside the valid file-offset range,
  exact-size hashes route `UINT32_MAX` through the 64-bit table, byte-compare
  converts absolute references to window-relative coordinates, and stateful
  logical/multipart signatures defer the append-time optimization to the
  authoritative full-file scan.
- CAB/CHM extraction limits now distinguish unlimited from exhausted budgets,
  fail closed on short writes or decoder errors, and remove partial temporary
  output when it exists. Rust bindings and their C/Rust layout assertions now
  include the widened matcher and logical-signature fields.

## Re-audit implementation follow-up

The 2026-08-10 re-audit findings were applied as source changes. The C90 hash
loop declarations, 64-bit sentinel collisions, exact-size hash boundary,
byte-compare window coordinate conversion, libmspack short-write/CHM policy,
positive harness controls, stale Rust layouts, append-state limitation, CAB
cleanup, centralized settings validation, and explicit supported-architecture
policy are now covered by source guards, focused unit-test additions, or both.

The source now produces a complete scanner build in the existing 900 MiB
Linux ARM64 Docker environment. That is build evidence, not 32 GiB runtime
certification. Linux x86-64 release scans, ASan/UBSan, broader adversarial
container fixtures, concurrency/resource measurements, daemon/milter
integration, and exact-boundary end-to-end evidence still must be produced on
the dedicated 64 GiB host before this fork can be called production-ready.

The reproducible runtime gate runner is now `tools/largefile_runtime_gate.sh`.
It refuses non-Linux and non-x86-64 hosts, verifies the scanner ELF
architecture, requires an explicit aggregate worker RSS budget, runs the sparse
boundary POC, checks the exact 32 GiB+1 policy rejection, records concurrent
worker RSS, verifies cancellation of a long-running edge scan, and fails
unless an ASan/UBSan scanner is supplied through
`CLAMAV_SANITIZER_CLAMSCAN`. Run it with an output directory outside the source
tree, for example:

    tools/largefile_runtime_gate.sh \
        /path/to/release/clamscan \
        /var/tmp/clamav-largefile-release-2026-08-13 \
        33554432

Set `CLAMAV_REQUIRE_SANITIZER=0` only for the non-sanitized runtime pass; the
separate sanitizer pass must use the default requirement. `CLAMAV_CONCURRENCY_LEVELS`
can expand the default `1 2 4` worker matrix after the target's memory budget
has been established. The output directory contains the build identity,
per-case logs, results, policy-rejection evidence, and concurrency measurements
needed for release review. A source checkout, source-only test, or ARM64 run
is not a substitute for this gate.

Release-gate concurrency is fixed to the exact-edge `32g-edge.bin` fixture, so
the resource measurement represents concurrent 32 GiB scans rather than a
smaller boundary sample. Use the lower-level POC harness for staged lower-size
tests; the release runner and evidence verifier reject those results as the
32 GiB worker budget.

## Runtime-gate execution handoff

The release workflow is intentionally manual because the exact 32 GiB edge
case can consume several GiB of resident memory and substantial scan time.
After this source tree is published to the private fork, run the ordinary and
sanitizer jobs from an x86-64 Linux runner with an explicit measured budget:

    gh workflow run cmake.yml --repo OWNER/REPO --ref BRANCH \
        -f run_largefile_runtime=true \
        -f run_largefile_sanitizer=true \
        -f rss_budget_kb=33554432 \
        -f min_available_kb=50331648 \
        -f 'concurrency_levels=1 2 4'
    gh run watch --repo OWNER/REPO
    gh run download --repo OWNER/REPO --name clamav-largefile-runtime-verified
    gh run download --repo OWNER/REPO --name clamav-largefile-sanitizer-verified

The uploaded artifacts, not the workflow's start or build status, are the
release evidence: inspect build-identity.txt,
host-preflight/host-preflight.txt, every results.tsv, the
32 GiB+1 rejection log, sanitizer logs, cancellation status, and the per-worker
RSS measurements before approving the fork. Run
`tools/largefile_runtime_evidence_check.sh` against each downloaded artifact,
passing the same RSS budget; it independently verifies those invariants and
rejects incomplete or over-budget evidence.

    tools/largefile_runtime_evidence_check.sh \
        /path/to/clamav-largefile-runtime-verified no '1 2 4' 33554432
    tools/largefile_runtime_evidence_check.sh \
        /path/to/clamav-largefile-sanitizer-verified yes '1 2 4' 33554432

The host preflight is provenance, not a memory-stability test. Validate the
deployment host's memory first, then use the preflight report to confirm that
Linux sees the expected 64 GiB and is not constrained by an unexpected cgroup
or shell limit.

The raw-scan POC has now addressed the `MaxFileSize` parser/clamp, the
ordinary AC/legacy absolute match-coordinate path, and calculated relative
offset caches. The current bounded-area audit also carries native logical,
YARA, macro, byte-compare, ZIP raw-catalogue, and OLE2 block-reader offsets
through 64-bit runtime coordinates. Fixed-width bytecode, PE version-info,
classic ZIP header, CFB sector-ID, and VBA stream fields remain bounded at
their ABI or format boundaries and are guarded explicitly.

The current audit also removes several artificial runtime limits: cumulative
INSTREAM quotas and scanner size-policy options now use 64-bit storage,
`fmap_readn()` returns a successful read larger than `INT_MAX`, and the
Microsoft archive adapter accepts offsets
that fit the platform's `off_t` instead of imposing a 2 GiB check. Archive
extraction budgets now use checked 64-bit remaining-size arithmetic and report
partial writes correctly. Calculated AC, BM, and PCRE target-relative offset
caches are 64-bit; fixed-width logical-signature, bytecode, and version-info
interfaces remain explicitly bounded where their ABI or format requires it.
Exact-size hash signatures retain the legacy 32-bit lookup table and add a
64-bit side table for sizes at or above 4 GiB, including `UINT32_MAX`. The boundary harness now reports only
offsets emitted by the engine; its independent marker-at-offset check is no
longer promoted to an engine-reported offset.

## Memory and resource budget

`MaxFileSize` and `MaxScanSize` are scan-policy limits, not RAM limits. A
file-backed map reserves virtual address space; resident memory depends on
pages touched, page tables, parser scratch buffers, decompression, extraction,
the loaded signature database, and the number of concurrent scans.

The implementation and deployment tests must measure:

- process RSS and virtual address space;
- system available memory and page-cache pressure;
- page faults, read throughput, CPU time, and temporary storage;
- one scan and concurrent scans at 1, 2, 4, 8, 16, and 32 GiB;
- parser scratch and decompression allocations;
- archive expansion, recursion, file-count, and scan-time limits.

Before a release-gate run, tools/largefile_runtime_gate.sh now captures a
Linux x86-64 host preflight under host-preflight/host-preflight.txt. The
report records physical and currently available memory, cgroup memory limits
and usage, CPU count, page size, shell resource limits, filesystem capacity,
and the available build/runtime tools. Its admission check uses the smaller of
host `MemAvailable` and finite cgroup headroom. This prevents a result produced
inside a small Docker or CI memory limit from being mistaken for evidence from
the 64 GiB deployment host. The release workflow defaults to a 48 GiB
effective-headroom floor (`50331648` KiB); a lower exploratory value must not
be promoted as production evidence.

Initial testing on the 64 GiB Ubuntu host should use one worker. Worker
concurrency must be chosen from measured peak resource use, not from the
32 GiB file limit. Keep PCRE and other contiguous-buffer consumers separately
capped until their
large-input behavior is designed and tested. An operating-system or
container-level memory ceiling should be part of the deployment test, with a
limit breach producing a visible non-clean/indeterminate result rather than a
clean verdict.

Sparse boundary files are appropriate for offset correctness. Materialized
files and adversarial containers are required for realistic I/O, cache,
decompression, and memory testing.

## Workstreams

1. Generate and classify the type/offset inventory.
2. Establish 64-bit build assumptions: `sizeof(size_t)`, `sizeof(off_t)`, and
   pointer width; require large-file support in the platform configuration.
3. Enforce the intentional 32 GiB `MaxFileSize` policy ceiling after parser
   and matcher gates are in place.
4. Widen raw matcher runtime coordinates while preserving signature-format
   widths and bytecode ABI compatibility.
5. Keep PCRE as a separately bounded subsystem until windowed or rolling
   behavior is specified.
6. Add versioned 64-bit exact-size hash indexing without breaking existing
   HDB/MDB databases.
7. Audit nested maps, extraction, parser limits, third-party boundaries,
   reporting, cache keys, callbacks, and legacy APIs. The current slice covers
   INSTREAM quota propagation, `fmap_readn()`, Microsoft archive offsets,
   calculated matcher offsets, ZIP search bounds, and exact-size hash keys.
8. Add boundary, differential, parser-adversarial, sanitizer, and workload
   tests before enabling 32 GiB defaults.

## Proof-of-concept results

The POC was built from ClamAV 1.5.3 in a 64-bit Linux ARM64 container. The
host is macOS ARM64, so this validates Linux/64-bit behavior but is not an
x86-64 deployment certification run.

The focused run detected and independently verified the marker position in
all of these sparse cases: 2 GiB−1, 2 GiB, 2 GiB+1, 4 GiB−1, 4 GiB, 4 GiB+1,
8 GiB, and 16 GiB. Peak RSS was approximately 452 MiB at 2 GiB, 876 MiB at
4 GiB, 1.72 GiB at 8 GiB, and 2.84 GiB at 16 GiB. Temporary storage remained
4 KiB per case.

The exact 32 GiB edge case reached approximately 3.56 GiB RSS and was killed
by the Linux/Docker memory environment with signal 9 after about 1:22; it did
not produce a clean verdict. This is a valid POC finding: increasing the file
limit does not imply that one worker can safely scan a 32 GiB sparse file in a
small-memory container. The 64 GiB Ubuntu x86-64 host must measure the same
workload with its actual kernel/container limits before enabling this mode.

## Remaining bounded paths

- PCRE full-map matching now uses the 64-bit-capable PCRE2 wrapper, but PCRE2
  still requires one contiguous subject. `PCREMaxFileSize` is therefore
  bounded by the 1 GiB single-allocation ceiling even when configured as zero
  or above 1 GiB. A required pass above the effective cap marks every active
  layer non-cacheable and returns an observable incomplete result.
- Bytecode globals and the bytecode `cli_bytecode_runlsig()` entry point remain
  `uint32_t` ABI. Native logical/YARA/macro/byte-compare offsets are now
  `uint64_t`; a bytecode-dependent logical signature is marked incomplete and
  cannot produce an unqualified clean result when an offset cannot be bridged.
- PE version-info matching remains a 32-bit RVA/hashset format boundary. A
  version-info match above 4 GiB is marked incomplete rather than silently
  treated as clean; this is distinct from the widened containing-file
  coordinates used by the native matcher.
- PE Authenticode and external-catalog hashes use native-width region
  coordinates and feed the digest in bounded 1 MiB fmap windows. Region
  overflow, short reads, digest failures, or another already-incomplete scan
  path prohibit trust and remain observable at the public scan result. PE
  section-signature hashes use the same bounded reader, and overlay offsets
  and lengths stay native-width until the fixed 32-bit bytecode metadata ABI;
  an unrepresentable bytecode bridge is marked incomplete.
- ZIP raw local-header catalogue coordinates and OOXML search results now use
  `size_t`, so large maps are not truncated before raw-header indexing. ZIP64
  central-directory placement is parsed with checked 64-bit offsets and is
  accepted only when the catalogue is contained by the fmap.
- OLE2 block byte offsets no longer stop at `INT32_MAX`; they are calculated in
  64 bits and checked against the native fmap range. CFB sector IDs and stream
  lengths remain format-defined 32-bit values, and malformed chains beyond
  the signed block-coordinate limit return `CL_EFORMAT`. VBA’s in-memory
  matcher still rejects a decompressed buffer above its legacy 32-bit API.
- Embedded PE metadata still carries a 32-bit containing-file offset for its
  compatibility ABI; embedded PE analysis marks offsets above 4 GiB
  incomplete with an explicit diagnostic while the raw signature scan
  continues.
- UDF allocation offsets, HFS+ block-to-byte conversions, and audited XAR/DMG
  extents use checked native-width arithmetic. XAR and DMG compressed input is
  consumed in bounded chunks, cumulative output limits are checked, and a
  decoder must reach its terminal state with the exact declared output.
  Malformed metadata, unknown non-empty methods, truncated streams, and
  configured-limit crossings are incomplete/non-clean rather than a scan of a
  partial prefix. Other format-specific boundaries still require dedicated
  adversarial and large-payload fixtures before an upstream support claim.
- Contiguous metadata/decompression remains intentionally capped: XAR TOCs and
  DMG XML at 64 MiB, NSIS contiguous input and EGG decoder buffers at the 1 GiB
  allocation ceiling. Crossing these limits is fail-visible; it is not full
  deep-parser support through 32 GiB.
- DMG blkx Base64 is prevalidated for its complete alphabet, quartet, padding,
  and suffix grammar while allowing XML whitespace and split text/CDATA.
  Stripe tables require exactly one zero-length final `END` record. Focused
  valid and malformed fixtures guard both rules, and the complete configured
  CTest suite passes with these checks enabled.
- BM offset mode now carries 64-bit runtime coordinates, but its bounded
  32-bit scan-window API still needs dedicated fixtures. PCRE full-map matching
  remains separately capped by `PCREMaxFileSize`.

## Acceptance criteria

LargeFile 1.0 is complete only when a 64-bit build can scan the complete
0–32 GiB range, detect signatures across the 2 GiB and 4 GiB boundaries,
report exact positions and sizes, preserve bounded memory behavior, and pass
the normal test suite plus the large-file suite under sanitizers. Unsupported
deep-parser paths must be explicit and observable.

## Proof-of-concept scope

The current implementation slice widens the direct raw-scan path, ordinary
AC/legacy signature match positions, and calculated AC/BM/PCRE relative offset
caches to 64 bits while retaining bounded scan windows. PCRE full-map scans now
pass 64-bit lengths to PCRE2, while the `PCREMaxFileSize` memory policy remains
enforced beneath the 1 GiB contiguous-allocation ceiling. Exceeding that cap,
a top-level `MaxFileSize`, or `MaxScanTime` cannot be reported as an
unqualified clean scan. The bounded-area slice extends native logical/YARA/macro/
byte-compare offsets and ZIP/OLE2 runtime coordinates without changing the
legacy bytecode or file-format ABIs. BM offset mode is no longer rejected
solely because its file position is above 4 GiB, but remains a separate
fixture-driven audit item because the scan-window API is bounded. The guarded
frozen-bytecode and fixed-format boundaries are deliberately fail-visible.
Exact 32 GiB, x86-64, and sanitizer release gates remain open until the
required build environment and fixtures are available. Run the
harness as follows inside a Linux build environment:

```sh
CLAMAV_CVD_CERTS_DIR=/path/to/test-or-production-certs \
  tools/largefile_poc.sh /path/to/clamscan /path/to/boundary-corpus /path/to/results
```

The harness reports non-clean resource termination separately from successful
detection and records the expected/actual fixture size, marker-at-offset
check, any offset emitted by the engine, RSS, page faults, CPU time, and
temporary-storage usage. A marker-at-offset result is not an engine match
offset unless the debug log contains that offset explicitly.
