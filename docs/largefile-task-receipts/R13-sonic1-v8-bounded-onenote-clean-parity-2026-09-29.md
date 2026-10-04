# R13 Sonic1 v8 bounded OneNote clean control — 2026-09-29

## Scope and identity

This is a **bounded 268,487,770-byte** clean-control scan of the same
fully allocated OneNote fixture used by
`R13-sonic1-v8-bounded-onenote-parity-2026-09-29.md`. It is not a full-size
parser or release qualification. The fixture SHA-256 is
`65edc62430899bd55aa27801a234b08af79bbab9314977dfe0ab2a7faf0641b1`;
the clean-control NDB SHA-256 is
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.
The v8 source manifest SHA-256 is
`f71a59692fd63357ba6f1ff362275cfadddfd20f6f01ac8b3edc5cb9ec99e723`.
The Release and C ASan/UBSan build-cache SHA-256 values are
`1ca43701cd73d194a326466578027445edb4dda5c0fe48332672d41ce8f4bde3`
and `df647e505b1ec18717e4d251bc1f5cb3500353536fd910a764aa87281fbbe07d`.
Host/profile/container identity is the same as the companion positive receipt.

## Result

The two direct clamscan controls, managed jobs
`job_5d874de9e4e04fdea4b2ee944a94c85c` (Release) and
`job_6f588bccf049441eb100a084338e10e4` (C ASan/UBSan), both exited 0.
Their JSON reports independently say `CL_TYPE_ONENOTE`,
`root_size=268487770`, `files_scanned=2`, `parser_operations=2`,
`detector_operations=2`, `skipped_operations=0`, `completion=COMPLETE`,
`verdict=0`, and 268,469,954 bytes of scanner-reported temporary high water.
Both isolated direct-scan spools were empty afterward. The direct report
SHA-256 values are
`ea8b510f92913805133044112dd1a02bd2fa7c52571a6bcbb8e8d6110bc1c3a1`
and `1e7f7610aaa18035b9270f2f9a9830b68ba16a219a80da2ea90820ccc07463aa`.
The sanitizer direct job had no stderr diagnostic.

The successful source-bound resource captures used the same limits and
`--force-to-disk=yes`, but 100-ms requested samples and no debug log:

| Build | MCP-SSH job / exit | Samples | RSS/PSS peak (KiB) | Sampled unique-inode temporary peak (bytes) | Swap/OOM/OOM kills |
| --- | --- | ---: | ---: | ---: | ---: |
| Release | `job_74766252413449b5bbe2ba9455e8a95f` / 0 | 15 | 35,300 / 32,562 | 261,292,032 | 0 / 0 / 0 |
| C ASan/UBSan | `job_90504863eeed4216895ed16bf374d22a` / 0 | 24 | 74,980 / 71,987 | 240,386,048 | 0 / 0 / 0 |

Both captured reports again say clean `COMPLETE` with zero skips. Both
captured spools were empty. The C ASan/UBSan run set
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`; its process log contained
no AddressSanitizer, LeakSanitizer, UndefinedBehaviorSanitizer, or `runtime
error:` diagnostic. Sampled temporary peaks need not equal the scanner's
internal high-water mark.

Evidence roots and artifact hashes:

| Artifact | Release: `/qualification/r13-v8-onenote256m-clean-capture2-20260929-release` | C ASan/UBSan: `/qualification/r13-v8-onenote256m-clean-20260929-asan` |
| --- | --- | --- |
| `scan-report.jsonl` | `ce8e75e997b450767794fc878340350370aadef91b02362fcf7336d03d3963e0` | `af77b44f3e13e362756d68f78479fb818cb9f7c554eb15e3d9f83d40509d8366` |
| `provenance/acceptance-case-resources.tsv` | `cc465c4da2d4b4351b28963569702dfa26ee16881cad065161dfad36aed9681d` | `c162ed85ec018b9f18b69dc19fe30c850722ea8d6c43af9eda58d45342f0c47f` |
| `provenance/samples.tsv` | `17e8db5c0ba2550dcc503c1f4af8a9679021392285af1748f8af8342735378ae` | `5ab01f2a75f501fec2b8c79afb28b6f38e192f549bf2a31bbc8167bbfd194f1a` |

## First capture diagnostic and boundary

An earlier Release resource-capture attempt, job
`job_b1d90550b0724ec48ef894fed98975d5`, used 10-ms samples plus debug
logging. It exited 1 before a structured report or resource row was written,
with no MCP-SSH stderr, and left about 257 MiB of case-private spool files.
No scanner/sampler process remained and the container cgroup's `memory.events`
reported `oom=0` and `oom_kill=0`. Its artifacts remain untouched under
`/qualification/r13-v8-onenote256m-clean-20260929-release`; the interrupted
`provenance/scan.log` hashes to
`c4f3f8653b8d1797c8c696d0ea3af1f933423967f0d606a87859e2ee9d9f21ba`.
The direct scans and changed-settings captures establish that the bounded
clean scanner path completes, but they do **not** explain the interrupted
capture. Do not count that first attempt as accepted evidence or remove its
spool before diagnosing its lifecycle.

Follow-up isolation kept the same v8 binary and fixture: a 10-ms capture
without debug logging (`job_15d4cfae0e994e14a93a3486c67ab02d`) passed
with a clean `COMPLETE` report, 23 process-tree samples, zero swap/OOM and an
empty spool. Its report/resource-row SHA-256 values are
`dbc7c0767536fe838c9de42014e4039672a4fde0674a2044ee3ff2796d7be81f`
and `e85fd9384b8230b9252785976b74d3dc15a8681a32ae2819885b41711b0e1ebd`.
A 100-ms capture **with** debug (`job_237f6545d98e44b780289d1a4ff2af83`)
again exited 1 without a report or resource row, leaving a case-private
spool. Its interrupted scan log SHA-256 is
`c322fbe30fe668fad871a96531077a57a7977d8c6690233da9f1d1e2e7ab12c6`.
The same debug scanner run *directly*, without the resource wrapper, passed
clean (`job_f877d40d764d4e638572cce0452fad0a`), wrote report SHA-256
`901f4cc05683b9dcc4763446da5c99aa1a27c97fdc287f111dc0fc3bbb6a1a6d`,
and left its separate spool empty. Container `memory.events` still reported
zero OOM and OOM kills. This isolates an interaction with live capture and
debug logging, not a demonstrated scanner clean-path regression; it does not
yet prove the exact cause. The failed artifacts remain under their separate
case roots.

The bounded positive and clean controls do not replace exact-32-GiB OneNote,
Rust sanitizer, production-CVD, privileged on-access, or final release
evidence. No capability status was promoted.

State: `development-verified; bounded-v8-clean-parity-passed; capture-10ms-debug-interruption-open; release-gates-open`
