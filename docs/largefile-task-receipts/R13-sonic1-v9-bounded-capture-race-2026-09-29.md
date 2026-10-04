# R13 Sonic1 v9 bounded capture retry and source-bound regression — 2026-09-29

## Scope and source identity

This is development verification of a narrow resource-sampler change, not
release qualification. The v8 resource wrapper intermittently exited 1 before
writing a report or resource row when scanning a bounded clean OneNote fixture
with debug logging. The same scanner completed without the wrapper; details
and preserved failed artifacts are in
`R13-sonic1-v8-bounded-onenote-clean-parity-2026-09-29.md`. The source review
found that `temporary_size()` could enumerate a spool file and then fail its
`stat()` if the parser unlinked it. The exact cause of those two v8 failures
was not directly observed, so this is a plausible race correction rather than
a proven root-cause attribution.

The v9 wrapper retries a whole temporary-tree snapshot up to five times when
an entry vanishes during enumeration; it never publishes a partial sum. It
still fails closed on persistent churn, missing root, symlinks, unsupported
entries and unrelated filesystem errors. Three focused new unit tests cover
the one-time race, persistent churn and non-retryable error. Locally,
`python3 -B tools/largefile_acceptance_resource_capture_test.py` passed
22/22, `sh tools/largefile_source_guards.sh` exited 0, and `git diff --check`
passed. The changed source was frozen anew, not mixed with v8 build evidence.

The deterministic package was 17,910,640 bytes, SHA-256
`9ab4c9ff3724a0fc26415a32c683a11fa24253e8092381d3fbc52ed27affb917`.
MCP-SSH durable transfer
`transfer_7ab91a6aa7c947c7813d5720fdd3a012` completed via a fresh
single-use handoff and atomic commit to
`/qualification/source-v9-temp-race-20260929.tar.gz` inside the pinned
container. The remote package SHA-256 matched. The extracted source is
`/qualification/source-v9-temp-race-20260929`; independently regenerating
its Git-less source manifest and comparing it byte-for-byte succeeded. Both
manifest hashes are
`884ba2f7a7e180a063c48bb62a8417e20277dee9c849c2f8e307bfdc50fb06b0`.
The manifest excludes qualification receipts/status metadata, but includes
the changed tool and its tests.

Host/profile: `sonic1` / `sonic1-camera-key`. The pinned container is
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image ID `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The current `/src` bind remains stale and was not used for v9. No software was
installed or fetched. The existing offline Cargo cache was copied to
`/qualification/cargo-v9-cache`, and build temporary files were kept on the
disk-backed qualification LV because the host-root LV was nearly full.

## Coherent Release build and tests

The full v9 Release configuration used the required qualification feature
options (application, clamonacc, milter, JSON shared, both library forms,
UnRAR, tests and large-file qualification tests). Configure job
`job_101d4b07288641ba810438d0f8b38873` and build job
`job_c443b8744c4f4358a7e689f23b5e30b8` both exited 0 with offline Cargo.
The CMake cache SHA-256 is
`6e80757e0e72b8fba04529ea43d9324670bb4e0848dd368c1edc175fe25addf5`;
the Release `clamscan` SHA-256 is
`83dee8840b488f79d95b636e6f914bb831b16d55c233bba6d2f943a4c9ffded9`.
Focused resource-capture CTest job
`job_858740779ee3408bbdd0f9b29ca12256` passed 1/1. The complete
non-edge Release CTest job `job_2dfef30441994a15999a242525df6343`
passed 32/32 in 117.76 seconds. The exact-32-GiB library case was explicitly
excluded from that suite and is separately tracked below.

## Live bounded clean/debug reproduction

Both runs used the same fully allocated 268,487,770-byte OneNote fixture,
SHA-256
`65edc62430899bd55aa27801a234b08af79bbab9314977dfe0ab2a7faf0641b1`,
and clean-control NDB, SHA-256
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.
The v9 Release scanner ran with debug logging, forced disk spooling and
process-tree sampling. Both formerly failing settings exited 0. Each report
said `CL_TYPE_ONENOTE`, clean `COMPLETE`, 2 files scanned, 2 parser and 2
detector operations, zero skips and 268,469,954 bytes scanner-reported
temporary high water. Each resource row binds the v9 source manifest,
Release CMake cache, and clean-control NDB. Both isolated spools were empty
afterward.

A separate read-only verifier exited 0 for both evidence roots. It checked
the source/build/DB hashes in each resource row, consecutive sample numbers,
strictly increasing timestamps, stable root PID and valid sampled PID sets,
trace-versus-row RSS peak equality, zero swap/OOM, empty temporary trees, and
the one clean `COMPLETE` OneNote report with the expected file, operation and
skip counts.

| Setting | Managed job | Evidence root | Samples | RSS peak (KiB) | Sampled temp peak (bytes) | Swap/OOM/OOM kill |
| --- | --- | --- | ---: | ---: | ---: | --- |
| 100 ms + debug | `job_362750c45283496fa9accb3ee6c39d70` | `/qualification/r13-v9-onenote256m-clean-debug-20260929-release` | 16 | 35,924 | 263,651,328 | 0 / 0 / 0 |
| 10 ms + debug | `job_eba2401c57f7400f96537942003e28c6` | `/qualification/r13-v9-onenote256m-clean-debug10ms-20260929-release` | 25 | 36,068 | 262,742,016 | 0 / 0 / 0 |

| Artifact | 100 ms SHA-256 | 10 ms SHA-256 |
| --- | --- | --- |
| `scan-report.jsonl` | `375ebbfea23b14bca738f3d96cba7d062a5f30a1b67fe201f4765d9ccf523147` | `388497f592068f54ed052d4736d8857b048944aed2a040a42c4ddf9af790d6d2` |
| `provenance/acceptance-case-resources.tsv` | `49e748cf79c35a9147a6e144c17f8371687325eb56e6338216470aac935ffdb5` | `8da3fc6935841a308472ea16ac34222fdae16a370f251fa4b8e8ba103c11b6cc` |
| `provenance/samples.tsv` | `574343846ee3fcb30bdecdddf0fda93a4f65f093927aca989ac8c17bb6b398f6` | `a7282ba6ad832f8df7a4038d3a258a403ae4debe4da9146aa3e6875afcaf8fad` |

The same 10-ms clean/debug case then passed with the v9 C ASan/UBSan
scanner, managed job `job_bee4e7d5470e4c3b8d49de703ad49e6b` (exit 0).
This used the same independently checksummed 268,487,770-byte fixture and
clean-control NDB, but a separate evidence root
`/qualification/r13-v9-onenote256m-clean-debug10ms-20260929-asan` and
sanitizer build-cache SHA-256
`1d2be36a7087eed76c5a4c88ceb93997edda5a5c64c5f23330b0efe57c50e5b6`.
The report again says clean `COMPLETE`, `CL_TYPE_ONENOTE`, 2 files, 2 parser
and 2 detector operations, and zero skips. The resource row records 35
samples, 75,032/72,193 KiB RSS/PSS peaks, 259,194,880-byte sampled
temporary peak, zero swap/OOM/OOM kills, and an empty post-run spool. The
scan used `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`; the retained debug log
contained no sanitizer diagnostic. A separate read-only verifier exited 0
after checking copied source/build/DB hashes, ordered trace/PID identity,
row-versus-trace RSS peak, clean report semantics, zero swap/OOM, no
diagnostic and cleanup.

| C sanitizer artifact | SHA-256 |
| --- | --- |
| `scan-report.jsonl` | `516c8602e936668d53adad74770ad18154f46f0019fcbe2e0cffd7459bb62f0e` |
| `provenance/acceptance-case-resources.tsv` | `07067625eca8bf8970bc513bca05af61b3e9572cc0b466706728cecda664b475` |
| `provenance/samples.tsv` | `82dae83a69a7a274bf985390fa6b7ea0ce66737357965c4e9bb1286f8b150741` |
| `provenance/scan.log` | `6a67ce864e1f113a3b800792017f081034ee7dac848136c011d1f5ced23398c1` |

The successful v9 repetitions support the race correction but do not prove
the exact v8 failure mode. The bounded case does not replace a 32-GiB
OneNote parse, C/Rust sanitizer parity, full PCRE phase proof, production-CVD
canary, privileged fanotify, or final release readiness. No capability was
promoted. At the last read-only preflight, Sonic1 still had about 23.6 million
KiB available memory with no swap and less than 19 GiB free on the
qualification LV. Full PCRE and certified service admission therefore remain
fail-closed; no volume resize or removal of the 32-GiB tmpfs fixture was
performed.

The v9 exact-edge library CTest subsequently passed under managed job
`job_fc9fafd6549e477bbad2b554a0dfbb3c`; its independent evidence checks
and post-run full fixture checksum are recorded in
`R05-sonic1-v9-library-exact32g-api-2026-09-29.md`.

State: `development-verified; bounded-v9-clean-debug-release-and-c-sanitizer-captures-passed; exact-three-api-parity-passed; release-gates-open`
