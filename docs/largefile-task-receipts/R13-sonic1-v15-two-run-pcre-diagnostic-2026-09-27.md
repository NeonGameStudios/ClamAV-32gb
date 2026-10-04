# R13 Sonic1 v15 exact-size two-run PCRE diagnostic — 2026-09-27

## Scope and provenance

This is a fresh, matching-source Sonic1 diagnostic of a positive PCRE tail
detection and a distinct clean continuation on the **same fully allocated,
disk-backed exact 32-GiB fixture**. It is not a matcher promotion or final
release qualification. Host/profile: `sonic1` / `sonic1-camera-key`.
Container:
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`;
image ID:
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The retained evidence root is
`/qualification/r13-pcre-v15-20260927` inside the container.

The clean v15 source manifest regenerated from the extracted tree and
verified as SHA-256
`e5b0d36e0ac086aed6c0d9fe7037ef0c3ba1fb9fd6f2b3ac38a14891c4e4b04f`.
The retained Release CMake cache/build identity hashes to
`f221a8694c14dfe964dddaf33ca36dfc53b33d4074928f0990cf1289ad56559f`;
`clamscan` hashes to
`5a4d6acdb1ebe06e750f68f82be66bb3af239c1dce74c91bdaecb66e249f88f8`.
Local and remote `matcher.c` and `scanners.c` hashes match. The fixture
`/ram/edge-stable.bin` is 34,359,738,368 bytes, with 34,359,746,560
allocated bytes, `SEEK_DATA(0)=0`, `SEEK_HOLE(0)=34359738368`, and
`EDGE-LATE-MARKER` at EOF−16. Its independently established SHA-256 is
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
The positive and nonmatching custom PCRE databases were each smoke-tested
against the 16-byte marker before the exact-size scans. Their SHA-256 values
are `3b7056c08f3bb0e2e0f86a71efe90bb0035cb7503844b6cbf5fd390c65087e8f`
and `b62c970a93761d1f4cf78834a0ddbface57028d4a6f6fbecfb5bdf4888ccf86c`.

## Results

The independent process-tree resource capture used 100-ms regular sampling
plus the application phase rendezvous; raw sample traces, phase logs,
process logs, JSONL reports, configuration, and resource rows are retained
in each run's subdirectory.

| Run | Tracked MCP-SSH job | Expected exit / completion | Samples | PCRE tree RSS peak | Post-PCRE tree RSS peak |
| --- | --- | --- | ---: | ---: | ---: |
| Tail detection | `job_8ea1c7cde9cd4488ab3876904f814b86` | 1 / `DETECTION_TERMINATED` | 1,561 | 33,639,132 KiB | 84,700 KiB |
| Clean continuation | `job_578db7986220481eab2de80f07df0ec6` | 0 / `COMPLETE` | 1,544 | 33,641,468 KiB | 87,036 KiB |

The positive JSONL report names `PcreTail32G.UNOFFICIAL`, proves
`root_size=contiguous_bytes=34359738368`, and has no skipped operations.
The raw debug log independently locates its regex match at
`34359738352` (EOF−16) and records the same object ID through before-PCRE,
PCRE, and post-PCRE release markers. Under `--allmatch` it also emits a
deep-parse dispatch marker; that detection-side marker is **not** the
independent clean-continuation proof.

The second JSONL report has `status=0`, `verdict=0`, `COMPLETE`,
`root_size=contiguous_bytes=34359738368`, zero skipped operations, and
no alert. Its separate raw log records before-PCRE, PCRE, subject release,
then the same-object deep-parse dispatch boundary in order. The distinct
databases and process executions prevent a positive detection from being
relabeled as a clean continuation.

Post-run fixture checksum job `job_5a842b08736d42f1b8cded42ef062f3b`
exited 0 and reproduced the same full-file SHA-256
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.

Both resource rows report zero process swap, zero new OOM events/kills,
and zero temporary peak bytes. Independent `awk` reductions of each raw
sample trace reproduced both reported PCRE and post-PCRE peaks. Both PCRE
peaks are below the 40-GiB R13 phase ceiling; both post-PCRE peaks are below
the strict 12-GiB threshold. Swap was disabled on the host. The 32-GiB
whole-workload subcase is a **separate, stricter contract**: these PCRE
peaks exceed its 33,554,432-KiB ceiling by 84,700 and 87,036 KiB
respectively, and cannot be presented as passes of that subcase.

Before these scans, the exact RAM copy at
`/dev/shm/clamav32gb-edge-20260926.bin` and the read-only disk-backed
`/ram/edge-stable.bin` both independently hashed to the fixture SHA-256
above. After the completed exact-library test, only the generated RAM copy
was removed, recovering about 32 GiB of RAM; the identical read-only
disk-backed fixture remains and can reproduce the input. Host
`MemAvailable` rose to 63,719,300 KiB, with `SwapTotal=0`.

## Acceptance boundary

The new local two-run proof verifier was developed **after** the v15 package
was frozen, so this retained diagnostic has not been promoted through a
matching-source proof-format-v2 release gate. The dedicated
`/qualification` volume had 55,148,384,256 bytes free after the runs
(about 51.4 GiB), below the required
68-GiB disk-backed staging admission; the root filesystem remained nearly
full. The `deep-parse` marker proves the dispatch boundary, not a parser
family's full coverage. Production CVD, service, fanotify, Rust address
instrumentation, remaining capability cases, and final readiness are still
open. No volume was resized or capability status changed.

No software was installed or downloaded, no GitHub workflow was changed or
triggered, and no commit or push was made.
