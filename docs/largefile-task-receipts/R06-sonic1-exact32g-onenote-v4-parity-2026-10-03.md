# R06/R12 Sonic1 exact-materialized OneNote v4 Release and C sanitizer parity — 2026-10-03

## Candidate and fixture identity

This receipt records one exact-size modern OneNote clean-control and late-child
pair on the current v4 source, in Release and C ASan/UBSan builds. It is a
targeted parser-family result, not all R06 fault/limit paths or overall R12
qualification.

- Candidate commit: 5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d on
  largefile-roadmap-qualification; the packaged working tree contained 160
  porcelain rows.
- Deterministic source package: 17,934,637 bytes,
  d298c08ba3f1f313e54da4d2c26bc9e456ab12ef19272e491bfda93dbba73421.
  Source-content manifest: 62bfd9df1d39f5a8081dcbd9458c50039f578c4f9bd694e9c2d017a8ad21a561.
  Fresh committed transfer: transfer_7e56655ba082452685e527d1f1ca0c08.
- Runner: Sonic1, login profile sonic1-camera-key; Linux x86-64; pinned
  container 450e8d8f297ffb0d8ace2900b2802bfb2a6f47b63ea40d1e48d0168fd7a41a6c,
  image sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df.
- Release clamscan SHA-256:
  5d34e22c09de3786834ea5679cab81c3b64bba9c075e26ae03fe6e2c246fe6e7;
  CMakeCache.txt:
  e0f80d7cd9e014384109b1ebb1fb936f1bd1159a2a75948e43543d579bdeec7a.
- C ASan/UBSan clamscan SHA-256:
  813579ab18ad2606c7907275b41b6db50f1e5ccb6aee06e8480e2cbdb7cabed1;
  CMakeCache.txt:
  2bb5d546f1398d301bd558279a8caf820978a648d80e92381916876271ab0a25.
  The build instruments C/C++ code; the verified/reused Rust archive was not
  built with Rust sanitizers.

The package’s 52,297-byte OneNote source hashes to
f5ae4bdb59719b8b9fde153ebcaf12a5b67c214de7c4083c0e968d3c3db0e02f and has
MZP at offset 33,342. The reviewed fixture generator inserted a zero-filled
ObjectDataBlob and produced an exact 34,359,738,368-byte regular file. Its
embedded MZP is at independently computed offset 34,359,719,413 (EOF-18,955).
The file was fully allocated (34,359,746,560 bytes), with no hole before EOF;
inode 11798295 and mtime_ns 1791004091890097218 stayed stable. The independent
full SHA-256 before and after all four scans was
1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf. Every
scanner log reported the same digest.

The clean private NDB contained a non-matching sentinel and hashes to
92afb199bbcec0ea69d87dd3c95fe20b8465f50f87749b98821fec0591c41972. The
positive private NDB contains
OneNote.Reader.LateMZ:0:0:4d5a50 and hashes to
18e92066983cbc35d84ccd8a1c83b09ddf73c965b4032b5930a4b6724965176b.
Neither run used production CVDs.

## Scan contract and results

Each run used MaxFileSize 32 GiB; MaxScanSize and MaxMatcherWork 64 GiB;
MaxContiguousSize and PcreMaxFileSize 32 GiB; MaxTemporarySize 64 GiB;
MaxScanTime 14,400,000 ms; force-to-disk; AlertExceedsMax; OneNote scanning;
cache disabled; and SHA-256 input logging. Each case had its own disk-backed
temporary spool and source-bound 100-ms process-tree resource capture.
Before runs, /tmp had 179,359,375,360 bytes free against a 108,447,924,225-byte
reserve, MemAvailable exceeded 65 billion bytes, and swap was disabled.

| Build / case | Exit / report | Parser result | Elapsed | Samples | Peak RSS / PSS | Temp-tree peak | Swap / OOM |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Release clean | 0 / COMPLETE | CL_TYPE_ONENOTE; 34,359,738,368 root bytes; 2 parser and 2 detector operations; 0 skipped | 300.187 s | 2,762 | 96,416 / 93,446 KiB | 34,345,844,736 bytes | 0 / 0 |
| Release late | 1 / DETECTION_TERMINATED | CL_TYPE_ONENOTE; OneNote.Reader.LateMZ.UNOFFICIAL; 2 parser operations; 0 skipped | 196.916 s | 1,855 | 96,220 / 93,240 KiB | 34,359,720,552 bytes | 0 / 0 |
| C ASan/UBSan clean | 0 / COMPLETE | CL_TYPE_ONENOTE; 34,359,738,368 root bytes; 2 parser and 2 detector operations; 0 skipped | 476.538 s | 3,490 | 137,580 / 134,538 KiB | 34,353,971,200 bytes | 0 / 0 |
| C ASan/UBSan late | 1 / DETECTION_TERMINATED | CL_TYPE_ONENOTE; OneNote.Reader.LateMZ.UNOFFICIAL; 2 parser operations; 0 skipped | 204.715 s | 1,662 | 137,128 / 134,148 KiB | 34,359,720,552 bytes | 0 / 0 |

All four structured reports record logical_bytes 34,359,738,912 and
temporary_bytes 34,359,720,552. Clean cases scanned 34,368,129,568 matcher
bytes; positive cases stopped after 544 matcher bytes. The positive exit code
1 is the expected detection status. Resource rows bind the common source
manifest to each exact binary and CMake configuration. All measured temp-tree
peaks were below 64 GiB; the per-case spool directories were empty afterward.
The cgroup OOM and OOM-kill counters remained zero, host swap remained zero,
and neither sanitizer run emitted an ASan, LeakSanitizer, or UBSan diagnostic.

The input fixture was removed only after its post-scan digest and metadata
matched, and after all four evidence trees were byte-for-byte copied to the
qualification volume. Durable evidence roots are
/qualification/r06-onenote-v4-exact32g-20261003/release-clean,
/qualification/r06-onenote-v4-exact32g-20261003/release-late,
/qualification/r06-onenote-v4-exact32g-20261003/asan-clean, and
/qualification/r06-onenote-v4-exact32g-20261003/asan-late. Fixture metadata
and hashes are in fixture-identity.json at the same root.

This is one current-source exact-size parser pair. It does not close malformed,
truncated, short-read, quota/timeout/cancellation or weak-recognition paths;
other parser families, all ingress/service variants, production-CVD behavior,
fanotify/on-access, Rust-source sanitization, and final release readiness
remain open. No capability was promoted.
