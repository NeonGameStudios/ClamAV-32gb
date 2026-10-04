# R13 Sonic1 v8 bounded OneNote parity — 2026-09-29

## Scope and identity

This is a current-v8 **bounded** parser and temporary-resource check, not
exact-32-GiB or release qualification. The Sonic1 `sonic1-camera-key` runner
used pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
and image ID
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Both case-local source-manifest copies hash to
`f71a59692fd63357ba6f1ff362275cfadddfd20f6f01ac8b3edc5cb9ec99e723`.
The v8 Release and C ASan/UBSan `CMakeCache.txt` identities hash to
`1ca43701cd73d194a326466578027445edb4dda5c0fe48332672d41ce8f4bde3`
and `df647e505b1ec18717e4d251bc1f5cb3500353536fd910a764aa87281fbbe07d`,
respectively. The isolated late-child NDB hash is
`18e92066983cbc35d84ccd8a1c83b09ddf73c965b4032b5930a4b6724965176b`.

The reused fully allocated OneNote fixture is
`/qualification/r13-v7-onenote256m-sampler-20260929-release/late-child.one`:
268,487,770 bytes, 524,392 allocated 512-byte blocks, SHA-256
`65edc62430899bd55aa27801a234b08af79bbab9314977dfe0ab2a7faf0641b1`.
Its embedded late `MZP` starts at byte 268,468,815, past the former 256-MiB
whole-input cap. The fixture was not modified.

## Results

Both scans used source-bound `largefile_acceptance_resource_capture.py` with
10-ms requested sampling, independent disk-backed temporary directories,
`--force-to-disk=yes`, JSON reports, the same NDB, 32/64-GiB scan ceilings,
and a 60,000-ms deadline. MCP-SSH jobs
`job_916bf252fc044523b6403708140fd8a3` (Release) and
`job_628e25d451994adda3384776fd1dd2ca` (C ASan/UBSan) each returned 1
for the expected detection; the resource wrapper retained a row from 17
process-tree samples in each case.

Both structured reports say `CL_TYPE_ONENOTE`, `root_size=268487770`,
`files_scanned=2`, `parser_operations=2`, `skipped_operations=0`,
`completion=DETECTION_TERMINATED`, and exact alert
`OneNote.Reader.LateMZ.UNOFFICIAL`. The scanner reported a temporary
high-water mark of 268,469,954 bytes in both cases. Its debug log recorded
the root fixture SHA and the extracted `clam.exe` late-child signature.

| Build | Sampled RSS/PSS peak (KiB) | Sampled unique-inode temporary peak (bytes) | Swap / OOM / OOM kills |
| --- | ---: | ---: | ---: |
| Release | 35,336 / 32,459 | 250,638,336 | 0 / 0 / 0 |
| C ASan/UBSan | 74,848 / 71,954 | 263,540,736 | 0 / 0 / 0 |

Both case-private temporary directories were empty afterward. The C
ASan/UBSan process log had no `AddressSanitizer`, `LeakSanitizer`,
`UndefinedBehaviorSanitizer`, or `runtime error:` diagnostic; the sanitizer
run set `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.

Evidence roots:

- `/qualification/r13-v8-onenote256m-sampler-20260929-release`
- `/qualification/r13-v8-onenote256m-sampler-20260929-asan`

| Artifact | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `scan-report.jsonl` | `aa6f0698716132eeb1c3a9abeb390034145ec2a322c400158407449fd52c330c` | `963519c52066e23d9258b8acacd710ffd2ad4a7ddd94cbc9f74ebf721548dc57` |
| `provenance/acceptance-case-resources.tsv` | `2feeb88d27e2f074dd4338d24728577de071b8df09d873c158b6c7a84b39f7c1` | `5c82d1fe88276222c94a637a483043d84d7a44feb0f43902c83fe78055675336` |
| `provenance/samples.tsv` | `55c3c4e2e65e80dda820dc5dc45716171002e0d404541dff4022fa8a9d78244f` | `ae16de0dbd6b3c686aaaebd5fecd98ffd9faf8e8faf924b04a48d12c93fa1c2d` |
| `provenance/scan.log` | `766ceda748b1a24b8e3f1b1cc93ce3c2cf03ac5e6192de9a83cf8b5a74ca0143` | `61bdd5147c4f0142ddfcba08a3c4435a38e1d65b9b7ab3a41ea0d0f6998c4ebc` |

## Boundary

This proves bounded current-source Release/C-sanitizer parity past the old
256-MiB reader cap. It does not substitute for a materialized exact-32-GiB
OneNote rerun, production-CVD behavior, Rust sanitizer evidence, or full
resource/service/on-access readiness. No capability status was promoted. The
host's current 48-GiB memory and 68-GiB disk admission failures are recorded
separately in `R13-sonic1-v8-resource-preflight-2026-09-29.md`.

State: `development-verified; current-v8-bounded-onenote-parity-passed; release-gates-open`
