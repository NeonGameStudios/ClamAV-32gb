# R13 Sonic1 v7 bounded OneNote sampler check — 2026-09-29

## Scope and provenance

This is a live, **bounded 256-MiB-payload** verification of the corrected
unique-inode temporary-tree sampler, not an exact-32-GiB qualification case.
The runner was `sonic1` / `sonic1-camera-key` in pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
(image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`).
The frozen v7 source package was transferred as
`transfer_f25284af5f9c4d72ad0db0d7612173e4`; its SHA-256 is
`4c61f7b0fad326770c936863992ad6f3f70f4fb5e5c56eec58b9cb3035c4dbdf`.
The remote extracted-source manifest was independently regenerated and
compared byte-for-byte with the embedded manifest. The case-local copies
of that manifest, Release `clamscan`, CMake cache and isolated NDB hash to
`72bb5de991f23098030c27f666578740b1ca74eaf0e7b3e1b9938735a70b2ebb`,
`0a8ea8421d6d0be1fd23f1d2458287fa24c4e927a9203baf0245494dd16ea2a0`,
`c312a602270217130f04e1a11e12bb4c5883dd58b5b5ee1b78037c3768a90992`,
and `18e92066983cbc35d84ccd8a1c83b09ddf73c965b4032b5930a4b6724965176b`.
The v7 Release build completed and its non-edge CTest suite passed 32/32
before this run. Subsequently the v7 C ASan/UBSan build and corrected
32/32 non-edge suite passed, as did the exact-edge three-API case in both
builds; the separate R05 v7 receipts contain that evidence.

## Bounded fixture and scan

The repository's 52,297-byte XOR-protected OneNote sample was decoded into
a fresh case-private directory, then the v7 fixture generator inserted a
physically materialized 268,435,456-byte ObjectDataBlob ahead of its
original data elements. The resulting `late-child.one` is 268,487,770
bytes, has 524,392 allocated 512-byte blocks, and hashes to
`65edc62430899bd55aa27801a234b08af79bbab9314977dfe0ab2a7faf0641b1`.
The decoded source hashes to
`f5ae4bdb59719b8b9fde153ebcaf12a5b67c214de7c4083c0e968d3c3db0e02f`.
An independent three-byte read found `4d 5a 50` at byte 268,468,815,
well beyond the former 256-MiB whole-input cap.

Managed job `job_0e5aa35554994535a47f7f9da1b1e031` used the v7
resource-capture helper at 10-ms requested intervals, a case-private
disk-backed spool, `--force-to-disk=yes`, the isolated late-MZ NDB, an
empty certificate directory, the same explicit 32/64-GiB ceilings as the
v6 full-size cases, JSON reporting, and input hash logging. It exited 1
for the expected detection. The wrapper successfully wrote an independent
resource row from 16 process-tree samples. The structured report says
`CL_TYPE_ONENOTE`, `root_size=268487770`, `files_scanned=2`,
`parser_operations=2`, `skipped_operations=0`,
`completion=DETECTION_TERMINATED`, and exact alert
`OneNote.Reader.LateMZ.UNOFFICIAL`. Its scanner-reported temporary high-water
mark is 268,469,954 bytes.

The corrected sampler's observed unique-inode temporary peak was
261,369,856 bytes; its 10-ms samples need not coincide with the scanner's
internal high-water mark. Sampled RSS/PSS peaks were 35,820/32,954 KiB;
swap, OOM and OOM-kill peaks were all zero. The case-private temporary
directory was empty after exit. Post-run `/qualification` free space was
33,191,288,832 bytes. The source-level hard-link case and independent
copy case are additionally covered by the 17/17 local capture-helper tests
in `R13-hardlink-temporary-sampler-correction-2026-09-29.md`.

Evidence root:
`/qualification/r13-v7-onenote256m-sampler-20260929-release`.

| Retained artifact | SHA-256 |
| --- | --- |
| `scan-report.jsonl` | `71c7908024b456401bd5b1e58dd52b3ec592a5dda12685113a852263acccbd62` |
| `provenance/scan.log` | `b7b5a000d34030ff9945df99a4794ec56002a40351a4d048132a03db61409b86` |
| `provenance/acceptance-case-resources.tsv` | `a4800e83f3f970846a905709987d7c43de83f1cd1c969c7afda9eeaefd6897b5` |
| `provenance/samples.tsv` | `5e7dee35c1cb00fb2e8df28a1c4e13b0b178e1db56a481b9e1074b0327e35a32` |

## C ASan/UBSan bounded parity

A second managed case, `job_a73be98f6c8f450baa4bdff4fe66bc5f`, scanned
the **same** 268,487,770-byte, already-hashed input with the frozen v7
C ASan/UBSan scanner and the same custom NDB and disk-spooling options.
It set `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`, used a separate
case-private spool, and exited 1 for the expected detection. The wrapper
completed a resource row from 21 samples. The structured report matched
Release on completion, `CL_TYPE_ONENOTE`, root/logical/matcher/temporary
bytes, two scanned files, two parser operations, zero skips and exact
`OneNote.Reader.LateMZ.UNOFFICIAL` alert; elapsed time was 1,294 ms.
The scanner log reported the input SHA-256
`65edc62430899bd55aa27801a234b08af79bbab9314977dfe0ab2a7faf0641b1`.

The sampled **unique-inode** temporary peak was 263,454,720 bytes,
versus the scanner's 268,469,954-byte internal high-water mark.
RSS/PSS peaks were 74,832/72,036 KiB, with zero sampled swap, OOM and
OOM kills. The separate temporary directory was empty after exit. The
source-manifest, scanner, cache and NDB copies hash to
`72bb5de991f23098030c27f666578740b1ca74eaf0e7b3e1b9938735a70b2ebb`,
`812a8b396786f5051d6523136e3e6b53d7cb8e520ce0739bf0ff9dc7e13d3949`,
`127534b6724c2b70285e823b9613dc4a4f8318966d9d0f10f17a54ed9b810f1f`,
and `18e92066983cbc35d84ccd8a1c83b09ddf73c965b4032b5930a4b6724965176b`.

Sanitizer evidence root:
`/qualification/r13-v7-onenote256m-sampler-20260929-asan`.

| Retained sanitizer artifact | SHA-256 |
| --- | --- |
| `scan-report.jsonl` | `811e784658b878afc373c76182aadd19ab911617b334eb0b68597e7f1ff86d72` |
| `provenance/scan.log` | `ea839f07ff8525936b3b481c58d47231f1f2238dd541644d097e5512d75c6186` |
| `provenance/acceptance-case-resources.tsv` | `577c43d0a72619128d3c2cecb85717b3235354260a16459bb4f39d744100bb0f` |
| `provenance/samples.tsv` | `2ff57b2831d00f1918fbc54892acc47893e004072c5e32229d769e6c986c90ce` |

## Qualification boundary

The first planned v7 full-size disk-spool scan was **not started**: its
preview was rejected because the qualification LV had only about 31.2 GiB
free while the scan could need nearly a 32-GiB spool. The bounded case
used less than 0.3 GiB and was allowed; it does not bypass or replace that
denial. The exact-32-GiB v7 positive, clean and sanitizer reruns require
safe additional headroom and, for LV growth, explicit user approval.
No capability was promoted. No software, usage reset, GitHub push, or
GitHub workflow was used.
