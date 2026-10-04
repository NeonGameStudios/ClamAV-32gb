# R08/R09 Sonic1 v15 UDF reserve and fuzzy-image utility development — 2026-09-29

This is two bounded source-bound Linux x86-64 development slices, **not**
full-size parser/matcher qualification or a release-ready candidate. The
dedicated qualification volume remained below the required admission floor.

## Frozen source and targeted build

The dirty canonical tree was packaged as
`/private/tmp/clamav-sigtool-v15-20260929.tar.gz` (17,929,063 bytes), SHA-256
`b1ed6fad2d39148f38b64e43a901ce497766a1f019f07e4d2a294cd959a80e02`.
Its source-content manifest SHA-256 is
`bfc38a4e7c26ad17d6b7ab0a73844b58e0fab5f200f812e0d92bdef7d3b2714f`.
MCP-SSH durable upload `transfer_f46873851ec044c2aac65607e24053fe`
committed by atomic rename after expected-size/checksum verification. The
package was extracted at `/qualification/source-sigtool-v15-20260929` in
Sonic1's pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`;
its independently regenerated Git-less manifest compared byte-identically
with the packaged manifest (`job_0904e4cfa34c4da7899fd714ab8658d1`,
exit 0; separate `cmp` exit 0). The package includes both the sigtool change
and the UDF reserve-sequence source/test edits. The UDF subagent reported a
capacity error after editing the shared checkout; those edits were inspected
and tested rather than assumed absent.

With the same Release, offline Rust/Cargo, large-file defaults, UnRAR,
milter, clamonacc, and WERROR configuration as v13, configure
`job_b403381933df43a6abd22fbaaa6e3cb6` exited 0. Targeted `sigtool`
build `job_872ff01de3f94b58a400dc205c5f1816` and `check_clamav` build
`job_77fe29cd9f1149c4bd91f6c8e49f2528` each exited 0 in
`/qualification/build-sigtool-v15-20260929-release`.

| Artifact | SHA-256 |
| --- | --- |
| `sigtool/sigtool` | `eb4e0013894fa6202d24df841e4998fe93b270dd9945861c0f61e93271f39047` |
| `unit_tests/check_clamav` | `3b729241691e97d3f06c0be59f7c4a589d2c29b9ec41a5c3b632896fb861ede1` |
| `CMakeCache.txt` | `8136f60d96041b3756b202665e616ad75770eb0622e79931802e549912d38c5f` |

## UDF reserve sequence

The anchored UDF path now selects the reserve descriptor sequence only when
the **entire** declared main sequence is all-zero blocks. A populated but
malformed main descriptor, mixed blank/populated main sequence, or malformed
reserve descriptor remains parse-incomplete and non-cacheable; malformed
content is not laundered through fallback. The existing descriptor tag,
sector-location, deadline, and extent checks still apply to the selected
sequence. Source-matched `CK_RUN_CASE=udf_corpus` in managed job
`job_9ec60b18c0964bb3817bb1ca2b7c0ae9` passed 1/1, including a valid
reserve-path late child detection and negative controls. The separate
`udf_map` suite passed 14/14. This is a conservative blank-main fallback,
not full UDF reserve/VDP/alternate-anchor qualification.

## Fuzzy-image utility

`sigtool --fuzzy-img` formerly malloced and read the entire encoded input.
The new path uses the existing fmap-backed Rust image decoder with a bounded
reader and decoder working-set admission. Both v13 and v15 produced the known
`logo.png: af2ad01ed42993c7` result. With the same 256-MiB **sparse-padding
unit control** (valid PNG ending at IEND) and no artificial memory cap,
per-child Linux `wait4` peak RSS was 274,872 KiB for the old v13 utility and
15,564 KiB for v15; both returned the same hash. The v15 utility also
returned a visible nonzero parser error on non-image `README.md`, with no
crash. Each ephemeral sparse-padding test directory was automatically
removed. This is not a materialized-large-image or 32-GiB scan result.

An initial test using `RLIMIT_DATA=192 MiB` was **invalid as a physical-memory
oracle**: fmap reserves virtual address space proportional to the source
length, and the kernel rejected that reservation even though resident pages
were bounded. The local regression was corrected after the v15 freeze to
measure per-child `ru_maxrss`, with a 128-MiB threshold that separates these
two observed implementations. The generated inventory was also refreshed
after the v15 freeze. Therefore v15's packaged test/inventory metadata is
not the current complete source; a new coherent package/build/guard run is
required before these changes can be candidate qualification evidence.

After the targeted builds, the dedicated LV had 2,217,680,896 bytes free.
No production database, full-size input, sanitizer, service, fanotify, or
release gate was run; no existing evidence was removed.

State: `targeted-v15-udf-and-fuzzy-development-passed; current-source-rebuild-and-full-qualification-pending`

## Follow-up: required-unsupported parser group on Sonic1

On 2026-09-29 at 18:00 UTC, the retained v15 `check_clamav` executable was
rehash-verified as
`3b729241691e97d3f06c0be59f7c4a589d2c29b9ec41a5c3b632896fb861ede1`,
matching the artifact above. Managed MCP-SSH job
`job_75e5495842d843c19003bf483c2cd3e6` ran that executable in the
retained v15 source's `unit_tests` working directory with
`CK_RUN_SUITE=cl_suite` and `CK_RUN_CASE=required_unsupported`; it exited 0
with **61 checks, 0 failures, 0 errors**. This focused group includes the
recognized AI-model, compiled-Python, and ignored-type parser controls.
The prior `test.log` and `test-stderr.log` were copied first and their
SHA-256 values matched the originals. The new run's logs were retained
without replacing those copies as
`test-required-unsupported-20260929T1800.log` (SHA-256
`f347648a4cbc8b1ddebdd221745594cc67a848aa5ef20e0e81936eddfed7655a`)
and `test-stderr-required-unsupported-20260929T1800.log` (SHA-256
`4302fef2a97790b711eaa776761433fc656a60ccb2fcac37c8a8aeb08a3e1e9f`)
under `/qualification/build-sigtool-v15-20260929-release/unit_tests`.
This strengthens Linux x86-64 development coverage for v15 only; the
current dirty tree has later edits, and this is neither full-size nor
sanitizer/release qualification.

## Follow-up: broader `cl_suite` attempt was invalid

Managed job `job_be17dbd33c764446bd6b166ff0df9857` attempted the broader
v15 `cl_suite` without moving its temporary directory off the nearly full
root overlay. The retained log reports `Checks: 2392, Failures: 944,
Errors: 0`; many failures were `mkdir(tmpdir, 0700) == -1`. Container `/tmp`
was on the root overlay, which reached **zero available bytes**. This is a
test-environment failure, not a passing or interpretable full-suite result.
The MCP-SSH job's root-overlay status/exit files were empty, so an exit code
cannot be claimed even though the test process no longer existed. The failed
logs are retained under the same dedicated-volume `unit_tests` directory as
`test-failed-cl-suite-root-full-20260929T1803.log` (SHA-256
`181c64b0c40383a20e1bdcb5f992842e77120ece0834835e39257e0287a9c194`)
and `test-stderr-failed-cl-suite-root-full-20260929T1803.log` (SHA-256
`ca4deb352b6ad96374a826cf4111de54d956eb1a5dc7edc336328c78dd3b1174`).

The exact 68,157,727-byte file created by that test in root `/tmp` was
copied to the dedicated volume as
`/qualification/build-sigtool-v15-20260929-release/unit_tests/cl-suite-failed-temp-20260929T1803.bin`.
Source and copy both hashed to
`045607e2258b6f7db3f2a65316a7a35af4876522a7434feb7ac59210a3f391f1`.
After verifying no open users, only the original root-overlay file was
removed; it is recoverable from the retained copy. Root overlay free space
then rose to 7,413,760 bytes, still unsafe for a broad rerun. Future suite
runs require an explicit temporary directory on the dedicated volume with
adequate headroom; this attempt must not be promoted as development or
release suite evidence.
