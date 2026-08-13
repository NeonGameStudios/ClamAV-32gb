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

The current source builds and links in the available Linux ARM64 Docker
environment, and its focused low-memory controls pass. The implementation is
still **not certified for production** because the exact 32 GiB workload has
not completed on the intended Linux x86-64 host. The required sanitizer,
memory, cancellation, daemon/milter, malformed-container, and concurrency
evidence is also not yet available from that host.

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

The development host is macOS and was not modified. Linux compilation and
small tests used an existing Debian ARM64 container capped at 900 MiB with
serial build settings. No multi-gigabyte scan was attempted in that container.
High-memory runtime proof is deliberately reserved for the 64 GiB Ubuntu
Linux x86-64 system.

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
| Runtime evidence | Gate implemented, real evidence open | The gate binds results to source/scanner hashes, verifies exact engine offsets and worker RSS, excludes sparse corpus payloads, creates `SHA256SUMS`, and publishes attested success artifacts separately from failed diagnostics. |

## Verification completed

The following evidence was produced in the memory-capped Linux Docker
environment against this milestone:

- the complete source tree, including `libclamav`, applications, test targets,
  and generated/XOR-decoded fixtures, compiled and linked;
- the Rust target built with Cargo 1.97 and `--locked`;
- the Rust FFI/layout CTest passed with one Cargo job;
- the matcher Check suite passed all 14 tests;
- valid InstallShield/NSIS detection checks and malformed/truncated NSIS
  fail-closed checks passed after the compatibility corrections;
- the complete configured CTest suite passed 10 of 10 tests, including
  `libclamav`, `clamscan`, `clamd`, `freshclam`, `sigtool`, Rust, milter quota,
  source guards, the POC control, and the evidence-verifier regression;
- focused nested-fmap, InstallShield, bytecode applicability, parser-cap,
  limit, timeout, ZIP, PE hashing, cache, stats, and fmap tests compiled;
- `clamav_milter_quota` passed;
- `largefile_poc_fail_closed`, `largefile_source_guards`, and
  `largefile_runtime_evidence_check` passed; and
- all large-file shell scripts passed POSIX syntax checking, while the GitHub
  Actions workflow parsed as YAML and uses immutable action revisions.

An initial Rust CTest attempt was killed because Cargo spawned parallel,
debug-heavy compiler processes inside the 900 MiB limit. Re-running the same
test with `CARGO_BUILD_JOBS=1` and test debuginfo disabled passed. This is
recorded as an environment-cap event, not a code or assertion failure.

The valid InstallShield and NSIS compatibility regressions exposed by an
initial `libclamav` CTest run were corrected. Focused detection and
negative-case checks pass, followed by a clean complete `libclamav` rerun and
a clean 10-test configured CTest run.

## Remaining release blockers

### 1. Exact 32 GiB execution is unproven

The historical ARM64 POC detected through 16 GiB. Its exact 32 GiB edge run
was killed after resident memory reached roughly 3.56 GiB. That result predates
the bounded fmap aging and parser work and therefore neither proves nor
disproves the current implementation. There is no current exact-edge result
from Linux x86-64.

Required closure:

1. Run 2, 4, 8, and 16 GiB characterization on the 64 GiB host.
2. Run exact 32 GiB head and edge detections and the 32 GiB+1 rejection.
3. Verify the engine-reported offset equals the fixture offset.
4. Record peak RSS, page faults, CPU, wall time, disk use, and cancellation.

### 2. Sanitizer and concurrency evidence is absent

The dedicated workflow must complete ASan/UBSan C/C++ build/tests and the
runtime matrix at worker counts 1, 2, and 4 within the configured aggregate
RSS budget. If a higher count is desired, it must be justified by measured
headroom rather than by the nominal file-size limit.

### 3. Full integration protocols remain to be proven at scale

The 64 GiB host must exercise actual clamd INSTREAM/FILDES and
clamav-milter transfers across 4 GiB and at the 32 GiB boundary. Pure quota
tests prove arithmetic but not socket framing, cancellation, temporary-file
behavior, or daemon lifecycle.

### 4. Fail-visible caps are not full deep-parser capability

PCRE subjects above 1 GiB; PDF/XDP/HWPML deep parsing above 64 MiB; XAR TOCs
or DMG XML metadata above 64 MiB; applicable legacy bytecode on inputs above
4 GiB; and bounded NSIS/EGG or unsupported archive encryption/compression
paths can produce an explicit incomplete/non-clean result. This is safe
failure behavior, but it is not evidence that every nested object up to
32 GiB receives every optional deep-analysis pass.

### 5. Broader parser compatibility remains a release qualification item

The complete configured normal suite passes after the InstallShield, NSIS,
and DMG fixes. Focused DMG fixtures cover split text/CDATA with XML whitespace,
invalid alphabet, misplaced padding, incomplete quartets, post-padding
suffixes, missing `END`, and non-final `END`. A broader real-world Apple DMG
corpus and multi-gigabyte malformed-container corpus still belongs in release
qualification; multi-segment DMGs remain intentionally unsupported and fail
visibly.

### 6. Release infrastructure must be exercised, not only reviewed

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
resource, and fail-open defects in the audited 32 GiB path. It is appropriate
to publish for review while high-memory and broader real-world compatibility
validation remain explicit blockers.

It is **not yet appropriate to publish as production-ready 32 GiB ClamAV**.
That designation requires the exact Linux x86-64 runtime, sanitizer,
concurrency, daemon/milter, and resource evidence described above, with no
clean verdict after incomplete inspection.
