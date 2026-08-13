# 32 GiB Large-File Fork Audit

**Audit date:** 2026-08-13
**Baseline:** ClamAV 1.5.3
**Audited tree:** `ClamAV-LargeFile 1.5.3-largefile-devel`
**Target:** scan inputs from 0 through and including 32 GiB on supported
64-bit systems without coordinate truncation, silent partial inspection, or
unbounded whole-input residency in paths that must be streamed
**Verdict:** **source-hardening candidate; production release remains blocked**

## Executive summary

The fork now has a coherent 64-bit raw-scan path and materially stronger
fail-visible behavior. The audit found and corrected defects that could wrap
match offsets, bypass signatures, invert nested scan results, trust an
incompletely hashed executable, scan only a truncated archive prefix, or let
resident memory grow with the complete input.

Commit `bba68110e04f78504d2af389050c349e01861315` now builds and passes its
normal and focused tests on the `sonic1` Ubuntu Linux x86-64 host. Its
one-worker runtime gate also detects the exact 32 GiB edge marker at engine
offset `34359738304`, and a separate warm-cache scan succeeds inside a hard
8 GiB memory-and-swap limit. These results close the earlier exact-edge and
single-worker raw-scan proof gaps.

The implementation is still **not certified for production**. Sanitizer
evidence, worker counts 2 and 4, clamd/milter large-transfer integration,
production-signature-database and deep-parser workloads, cold-cache behavior,
and known false-clean and ZIP strong-encryption gaps remain open.

Large-file support in this tree must therefore be understood as follows:

- Native raw matching, scan accounting, cache keys, stats, and the audited
  bounded container paths retain 64-bit file coordinates.
- Fixed-format and legacy ABIs remain fixed-width where required. If a
  necessary inspection cannot represent the input, the scan is marked
  incomplete and cannot be reported or cached as clean.
- Contiguous parsers have explicit caps. Exceeding one is a visible non-clean
  result, not successful support for an object of that size.
- The upper policy bound is 32 GiB. This is not an unlimited mode and does not
  imply that 32 GiB of RAM may be consumed.

## Scope and constraints

The review covered:

- AC/BM matching, logical signatures, exact-size hashes, PCRE, byte-compare,
  and bytecode bridges;
- fmap paging and aging, I/O-failure handling, cache keys, stats, callbacks,
  and C/Rust layouts;
- ZIP/ZIP64, CAB, CHM, UDF, GPT, AutoIt, XAR, NSIS, EGG, DMG, InstallShield,
  PE/AuthentiCode, PDF, XDP, and HWPML paths;
- clamd/clamdscan streaming and clamav-milter quotas;
- size/time policy propagation; and
- the boundary corpus, POC harness, evidence verifier, CTest registration,
  and GitHub Actions release gates.

The development host is macOS and was not modified. Earlier compilation and
small tests used a constrained Debian ARM64 container. Current runtime
validation used the real `sonic1` Ubuntu Linux x86-64 system, with Docker used
to isolate the build and scans. The 8 GiB result was produced by a separate
container with hard memory and memory-plus-swap limits of 8 GiB, four CPUs,
and no additional swap allowance. It was a warm-cache sparse raw-file test,
not a cold-cache or production-workload certification.

## Remediation status

| Area | Status | Audited disposition |
|---|---|---|
| Matcher offsets and sorting | Source-fixed and focused-tested | BM uses an explicit 64-bit comparator; native sentinels cannot collide with valid 32-bit-boundary offsets; absolute/window coordinates and byte-compare overlap de-duplication are checked. |
| Signature size/offset parsing | Source-fixed and focused-tested | Logical `FileSize`, calculated offsets, and exact-size hash keys retain native 64-bit values; reserved sentinel values are rejected. |
| PCRE | Fail-visible bounded support | PCRE subjects are capped by the 1 GiB contiguous-allocation ceiling. A required skipped pass marks all active layers incomplete and non-cacheable. |
| Bytecode | Fail-visible ABI boundary | The legacy bytecode ABI remains 32-bit. Maps or offsets that cannot be represented are rejected only when an applicable hook would run, and the result is incomplete/non-clean. |
| fmap and hashing | Source-fixed and synthetic-tested | Aging uses a persistent bounded cursor and release budget; read failures roll back page state and return `CL_EREAD`; hash and extraction readers use bounded windows. |
| Cache, stats, and FFI | Source-fixed and focused-tested | File sizes are 64-bit in cache/stat records and JSON; checked-in Rust layouts match the widened C structures and have layout assertions. |
| Top-level limits and timeout | Source-fixed and focused-tested | `MaxFileSize` overflow and `MaxScanTime` cannot become an unqualified clean verdict. Detection and critical-error precedence is preserved. |
| ZIP and ZIP64 | Bounded core methods implemented | Stored, Deflate, Deflate64, BZIP2, Implode, and ZipCrypto use bounded input. Decoder terminal state, exact output, input exhaustion, and callback status are enforced. ZIP64 coordinates are checked and native-width. Unsupported methods and strong encryption are incomplete/non-clean. |
| CAB and CHM | Source-fixed | Short writes, exhausted budgets, decoder failures, and partial temp output are fail-visible; partial members are not scanned as complete. |
| PE/AuthentiCode | Source-fixed and focused-tested | AuthentiCode/catalog/section hashes use checked native-width regions and 1 MiB reads; incomplete hashing prohibits trust. Overlay sizes remain native-width until an explicitly checked legacy bridge. |
| PDF, XDP, and HWPML | Fail-visible bounded support | Whole-map materialization was removed from audited entry paths. Legacy deep parsers have explicit 64 MiB caps; HWPML Base64 is streamed with strict quartet and padding validation. |
| Nested fmap and InstallShield | Source-fixed and focused-tested | Nested ranges are strict and forced-to-disk copies are chunked. InstallShield does not scan capped or malformed partial output as complete. |
| UDF, GPT, AutoIt, XAR, NSIS, and EGG | Hardened in this milestone | Result inversion, unchecked arithmetic, partial-decode success, unknown non-empty methods, and whole-input decoder reads were converted to checked, bounded, fail-visible paths. |
| DMG | Source-fixed and focused-tested | XML and compressed stripes are bounded; fork-relative offsets, stripe geometry, exact output, decoder completion, time limits, and multi-segment rejection are checked. Blkx Base64 now validates the complete alphabet, quartets, padding, and suffix while allowing XML whitespace, and each stripe list requires exactly one zero-length final `END` record. |
| clamdscan and milter | Source-fixed; quota test passes | Client-side stream truncation is rejected; milter totals and reservations are checked 64-bit values with exact-boundary and overflow tests. |
| Runtime evidence | One-worker x86-64 gate passed; release matrix open | The gate binds results to source/scanner hashes, verifies exact engine offsets and worker RSS, excludes sparse corpus payloads, creates `SHA256SUMS`, and publishes attested success artifacts separately from failed diagnostics. Commit `bba68110e04f78504d2af389050c349e01861315` passed the one-worker gate on `sonic1`; sanitizer and multi-worker evidence remain outstanding. |

## Verification completed

The following evidence was produced on the `sonic1` Ubuntu Linux x86-64 host
for exact code commit `bba68110e04f78504d2af389050c349e01861315`:

- the full Release configuration built to 100% with `ENABLE_STATIC_LIB`,
  `ENABLE_EXAMPLES`, and `ENABLE_MILTER` enabled;
- focused `libclamav`, `clamscan`, and examples tests passed 3 of 3;
- focused Valgrind tests passed 2 of 2;
- the complete non-Rust CTest selection passed 16 of 16 in 1106.34 seconds;
- an isolated writable exact source clone passed all 62 Rust tests;
- the patched one-worker runtime gate exited 0 and recorded
  `runtime_gate=pass`;
- all 11 sparse boundary rows detected their markers and reported the exact
  engine offsets, including the exact 32 GiB edge at `34359738304`;
- the 32 GiB+1 policy rejection passed, cancellation returned the expected
  status 124, and the one-worker concurrency check passed with aggregate RSS
  of 100792 KiB; and
- a separate warm-cache exact-edge scan in a container hard-limited to 8 GiB
  memory, 8 GiB memory-plus-swap, and four CPUs reported `FOUND` in 1:49.95,
  with 100944 KiB peak RSS and zero swap use.

The 8 GiB result demonstrates that the sparse raw exact-edge case does not
require RAM proportional to the file size. It does not establish the memory
requirements of a production signature database, deep parsers, materialized
32 GiB input, concurrent workers, or a cold page cache.

## Remaining release blockers

### 1. Sanitizer and multi-worker evidence remains open

The dedicated workflow must complete ASan/UBSan C/C++ build/tests and runtime
evidence. Worker counts 2 and 4 must pass within the configured aggregate RSS
budget. The successful one-worker run does not predict parser scratch use or
database residency under multiple concurrent production scans.

### 2. Full integration protocols remain open at scale

The 64 GiB host must exercise actual clamd INSTREAM/FILDES and
clamav-milter transfers across 4 GiB and at the 32 GiB boundary. Pure quota
tests prove arithmetic but not socket framing, cancellation, temporary-file
behavior, or daemon lifecycle.

### 3. Production workload and cold-cache certification remains open

The passing gate uses sparse files and a purpose-built boundary signature.
Production signature databases, materialized files, cold-cache reads, and
malformed or expanding deep-parser workloads must be characterized for RSS,
page-cache pressure, temporary storage, latency, and failure behavior. The
warm-cache 8 GiB result must not be treated as a minimum-RAM guarantee for
production deployment.

### 4. Known false-clean and ZIP strong-encryption gaps remain open

Some generic size, recursion, and file-count limit paths can still normalize
an incomplete inspection to success unless the sticky incomplete state is
set. ZIP strong-encryption and related masked/encrypted fallback cases also
need an explicit incomplete/non-clean disposition. Until those paths are
closed and regression-tested, an apparently clean result is not universally
proof of complete inspection.

### 5. Fail-visible caps are not full deep-parser capability

PCRE subjects above 1 GiB; PDF/XDP/HWPML deep parsing above 64 MiB; XAR TOCs
or DMG XML metadata above 64 MiB; applicable legacy bytecode on inputs above
4 GiB; and bounded NSIS/EGG or unsupported archive encryption/compression
paths can produce an explicit incomplete/non-clean result. This is safe
failure behavior, but it is not evidence that every nested object up to
32 GiB receives every optional deep-analysis pass.

### 6. Broader parser compatibility remains a release qualification item

The complete configured normal suite passes after the InstallShield, NSIS,
and DMG fixes. Focused DMG fixtures cover split text/CDATA with XML whitespace,
invalid alphabet, misplaced padding, incomplete quartets, post-padding
suffixes, missing `END`, and non-final `END`. A broader real-world Apple DMG
corpus and multi-gigabyte malformed-container corpus still belongs in release
qualification; multi-segment DMGs remain intentionally unsupported and fail
visibly.

### 7. Release infrastructure must be exercised, not only reviewed

The repository expects a self-hosted runner labelled
`clamav-largefile-64gb`. A real workflow run must prove that runner capacity,
cgroup headroom, toolchain, immutable source revision, artifact hashes, and
attestation publication all work together. A locally manufactured evidence
directory is not release provenance.

## Required production acceptance gate

Use the manual GitHub Actions inputs only on the dedicated Linux x86-64 host:

```sh
gh workflow run cmake.yml --repo OWNER/REPO --ref BRANCH \
  -f run_largefile_runtime=true \
  -f run_largefile_sanitizer=true \
  -f rss_budget_kb=33554432 \
  -f min_available_kb=50331648 \
  -f 'concurrency_levels=1 2 4'
```

Successful evidence artifacts are named:

- `clamav-largefile-runtime-verified`
- `clamav-largefile-sanitizer-verified`

The artifact must exclude `corpus/`, contain `runtime_gate=pass` in
`build-identity.txt`, pass `tools/largefile_runtime_evidence_check.sh`, match
its `SHA256SUMS`, and have a GitHub build-provenance attestation for that
manifest. Failed diagnostic artifacts must not be promoted as release
evidence.

## Final verdict

This milestone materially closes the previously identified coordinate,
resource, and fail-open defects in the audited 32 GiB raw path. Commit
`bba68110e04f78504d2af389050c349e01861315` has credible Linux x86-64 proof
for exact-offset raw detection through 32 GiB, the 32 GiB+1 policy boundary,
cancellation, and one-worker operation, including a warm-cache exact-edge scan
under a hard 8 GiB memory-and-swap ceiling.

It is **not yet appropriate to publish as production-ready 32 GiB ClamAV**.
That designation still requires sanitizer and 2/4-worker evidence,
large-transfer clamd/milter integration, production-database/deep-parser and
cold-cache resource qualification, and closure of the known false-clean and
ZIP strong-encryption gaps described above.
