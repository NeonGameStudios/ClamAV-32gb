# R12 Sonic1 v8 raw exact-32-GiB clean scan — 2026-09-29

## Why this rerun was needed

The v7 C ASan/UBSan raw clean scanner wrote a `COMPLETE`, status-0,
34,359,738,368-byte report, but its resource wrapper exited 1 and did not
write `acceptance-case-resources.tsv`. Managed job
`job_021957a5e2ec4fa2b2fc02e646652a74` reported that
`largefile_procfs_tree_metrics.py` lost selected PID 1482901 at scanner
exit. The report (`47e57b2d749b443b6905ee2865c14484e802a62174cf27bd98bbaad51b4a3af4`),
log (`c6f016f2555c018871856b86dbbfcee83036ffaf73eecd2b3c60d22359a621a7`),
and 184,471-byte sample trace (`c4ab1828a6fcb1a3fb85111672499fdbc60b529e7e57fe231dfcb8d5288acaea`)
remain at `/qualification/r12-v7-raw-clamscan-clean-20260929-asan`.
This is diagnostic evidence, **not** a qualified sanitizer clean case.

The wrapper now classifies only the exact selected-root-disappearance
diagnostic and permits the last failed sample only after a bounded `wait()`
confirms process exit. Any other sampler error while the process is live,
or a disappeared root with a still-live child, remains fail-closed. The
local source-guard suite and 19/19 wrapper tests passed; the same 19/19
wrapper tests passed on Sonic1.

## Frozen v8 source and Release build

Authorized runner: `sonic1` / `sonic1-camera-key`; pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The fresh deterministic archive was sent by MCP-SSH transfer
`transfer_095efe00411f41f6b46881a6be074880`: 17,909,696 bytes,
SHA-256 `785494e0713a0e5a8cbef44a4f63dd5a7e36a61a6954e5b5e7262b383706bca3`.
The transfer completed and committed. Source was extracted at
`/qualification/source-v8-procfs-exit-race-20260929`, and a Git-less
manifest regenerated there compared byte-for-byte with the embedded
manifest. Both hash to
`f71a59692fd63357ba6f1ff362275cfadddfd20f6f01ac8b3edc5cb9ec99e723`.
No older transfer ledger record was used for provenance.

The fresh Release build at
`/qualification/build-v8-procfs-exit-race-20260929-release` completed,
including a second no-op build confirming 100% of targets. Its CMake cache
embeds the v8 source-manifest hash in both source identity fields.
The case-local `clamscan` hashes to
`6709ea869b8f800d63bce27c024350d41abc6b78fc3ebdef0a73fb75c2e0da04`,
and the case-local CMake cache to
`1ca43701cd73d194a326466578027445edb4dda5c0fe48332672d41ce8f4bde3`.
The initial build attempt failed because Rustup's default home was
root-owned; the successful retry used the already installed stable
toolchain and existing writable offline Cargo cache. No software was
installed. Managed CTest job `job_e2f11a282c91497eb2decfeb705560e6`
passed **32/32 non-edge tests**, excluding only
`largefile_library_exact_32g`, in 245.52 seconds.

## Release raw clean case

The pre- and post-run fixture stat was unchanged: size
34,359,738,368 bytes, 67,108,880 allocated 512-byte blocks, inode
8149459, mtime 1790047133. The exact `EDGE-LATE-MARKER` was read at
EOF minus 16. The preexisting full-file SHA-256 oracle is
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
The isolated `clean-control.ndb` hashes to
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`;
the independent v7 bounded binary oracle read all bytes and proved that
its clean-control literal does not occur in this fixture.

Managed job `job_850f81c230cd4457bab0a85f183072f3` used the v8
Release `clamscan`, explicit 32/64-GiB scan and temporary limits, an
empty case-private certificate directory, JSON reporting, hash logging,
and a case-private disk-backed temporary directory without forced
disk spooling. It exited 0. The structured report says status/verdict
0/0, `COMPLETE`, `CL_TYPE_BINARY_DATA`, root/logical size
34,359,738,368, matcher bytes 34,368,129,024, one scanned file,
zero skips and zero temporary bytes. Scanner elapsed time was 191,896 ms;
its log reports the expected fixture SHA-256 and `/ram/edge-stable.bin: OK`.

The resource wrapper completed 1,834 process-tree samples. The case row
records RSS/PSS peaks 100,992/98,069 KiB and zero sampled swap,
temporary, OOM and OOM-kill events. An independent read-only verifier
checked the case-local source/binary/cache hashes against the row,
all 1,834 consecutive sequence numbers and increasing timestamps,
stable root PID inclusion, trace/row RSS peak equality, report fields,
log verdict and hash, and empty post-run spool; it exited 0.

Evidence root: `/qualification/r12-v8-raw-clamscan-clean-20260929-release`.

| Artifact | SHA-256 |
| --- | --- |
| `scan-report.jsonl` | `01fd516f6b072dd605dddd2e0887ce60b31d117059a03039ab45f1f706e56203` |
| `provenance/scan.log` | `cab81063916296bead4b8c823752ce49e2cb8d67c6391f70e0d161c9a8db30bb` |
| `provenance/acceptance-case-resources.tsv` | `fdce266ae067505c771194562b61f4507184614c2a695f11e5f0ccfed3674496` |
| `provenance/samples.tsv` | `6b73b442156c7b9c8335d1079e1739883e1e456fae9c8dcb21c08616f5499e3b` |

## C ASan/UBSan raw clean parity

The fresh v8 sanitizer build at
`/qualification/build-v8-procfs-exit-race-20260929-asan` used
`RelWithDebInfo`, C/C++ address and undefined-behavior instrumentation,
instrumented executable/shared linkers, static and shared libraries,
and the same large-file options as v7. It built to completion; a no-op
rebuild confirmed all targets. Both source identity fields in the cache
equal the v8 manifest hash. Managed job
`job_537472de1bed41ba952e84a3f05deab6` passed **32/32 non-edge
CTests** with the existing offline Cargo cache and sanitizer environment,
in 413.42 seconds. The case-local scanner hashes to
`0eade76a1ccb1761994568934361661f26facd163d01a1ee84dac1e69dda5876`,
the cache to
`df647e505b1ec18717e4d251bc1f5cb3500353536fd910a764aa87281fbbe07d`,
and the clean-control NDB and source manifest match the Release case.

Managed job `job_37423c4fd45b41bcbd6df6db9b555724` repeated the
raw clean scan with `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`, a separate
case-private spool and evidence root, and the corrected v8 wrapper.
It exited 0, and the wrapper **wrote the resource summary** from 2,666
samples; the v7 end-of-process sampling failure did not recur.
The report says status/verdict 0/0, `COMPLETE`, `CL_TYPE_BINARY_DATA`,
the same exact root/logical/matcher byte counts as Release, one scanned
file, zero skips and zero temporary bytes. Scanner elapsed time was
337,026 ms. The scanner log reports the expected fixture SHA-256 and
`/ram/edge-stable.bin: OK`, without ASan/UBSan/LSan diagnostics.

The case resource row records RSS/PSS peaks 140,872/137,964 KiB,
zero sampled swap, temporary, OOM and OOM-kill events. An independent
read-only verifier checked the report, case-local source/binary/cache
hash binding, all 2,666 consecutive sequence numbers and increasing
timestamps, stable root PID inclusion, trace/row RSS peak equality,
scanner log and absence of sanitizer diagnostics, and empty post-run
spool; it exited 0. The fixture size, allocated blocks, inode and
mtime were unchanged after this run.

Sanitizer evidence root:
`/qualification/r12-v8-raw-clamscan-clean-20260929-asan`.

| Artifact | SHA-256 |
| --- | --- |
| `scan-report.jsonl` | `18380b04dec248e5d43029c363f1a56db9906a87da3fb19f68a94d3c3b5c4b3b` |
| `provenance/scan.log` | `82613f355e4e35fd7ed46511a27d8017ceaff06da33c257643113bbed9adab91` |
| `provenance/acceptance-case-resources.tsv` | `662cd50018596856b2d5c8a6b67473d1c6ba6c68b47dc0b779f557dd5ab416ad` |
| `provenance/samples.tsv` | `98573103bd89965426cf43cbb9e50a93d2270a385da959ef3dfbb447d8b7c0e2` |

These are raw-file clean cases, not the full OneNote disk-spool case.
They do not promote a capability or final release readiness. The
qualification LV had only 21,637,840,896 bytes free before the sanitizer
scan, less than a full 32-GiB spool; no full-size OneNote case was started.
