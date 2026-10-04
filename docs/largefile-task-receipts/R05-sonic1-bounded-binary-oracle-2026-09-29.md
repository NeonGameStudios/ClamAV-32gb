# R05 Sonic1 bounded binary fixture oracle — 2026-09-29

## Why this tool exists

Line-oriented `grep -a` grew on the newline-free, fully allocated 32-GiB
fixture and was OOM-killed. The failed attempt and host counter transition
are retained in `R12-sonic1-v3-clean-exact-2026-09-29.md`; it is not
qualification evidence. R05 needs an independent, reproducible content and
materialization oracle that cannot retain a whole 32-GiB line.

`tools/largefile_binary_literal_oracle.py` now streams fixed 4-MiB blocks,
hashes every byte, carries only the bounded `needle_length - 1` overlap,
requires an expected size and SHA-256, and checks each expected literal's
exact occurrence count/offset. Optional `--require-materialized` rejects
fewer allocated bytes than file size, requires `SEEK_HOLE` to return EOF,
and retains the actual first-hole offset in JSON. It rejects symlinks,
changed metadata, hash/size mismatches, repeated or missing literals, and
unsupported materialization checks before emitting success JSON. The tool
does not infer a scanner verdict or turn a sparse metadata probe into a
materialized fixture.

The source-controlled script SHA-256 is
`cbfe3aa36164347e42181c25e8698b1e1f6bae20ff8a721303d375fe029b7024`
(7,846 bytes). Its eight local regression tests passed, including
cross-block matching, absence, duplicate-marker failure, hash/size failure,
symlink rejection, and fail-closed `SEEK_HOLE` behavior; the test is now
registered as `largefile_binary_literal_oracle` in
`unit_tests/CMakeLists.txt`. No software was installed.

## Live Sonic1 check

The final script was transferred as a small text file to the Sonic1 host
path
`/tmp/clamav-qualification-disk-lv-v1/r13-v32-d2531599f754-mcp108/r05-binary-oracle-v2-20260929.py`
(the qualification container would see it under `/qualification`); independent Sonic1
`sha256sum` matched the source hash above. Managed job
`job_954fec912a0242f68685b41ed16d7070` ran it against the read-only
`/ram/edge-stable.bin` fixture with `--require-materialized`, expected size
34,359,738,368, expected SHA-256
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`,
`edge:454447452d4c4154452d4d41524b4552:34359738352`, and
`clean:434c414d41562d544553542d535452494e472d4e4f542d4549434152:absent`.

The managed command was `python3 -B` followed by that script path and
`--file /tmp/clamav-qualification-20260921-portable3b/build/transfer-v30/fixture-v30/edge-stable.bin`,
`--expected-size 34359738368`,
`--expected-sha256 98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`,
the two `--case` values above, and `--require-materialized`.

The job exited zero with empty stderr and one JSON result: all
34,359,738,368 bytes read; exact expected SHA-256; 34,359,746,560
allocated bytes; `first_hole_offset=34359738368` (EOF); one edge marker
at 34,359,738,352 (EOF−16); zero clean-control markers; stable metadata.
The host OOM-kill count remained at its pre-run baseline of 47, with no
swap. This is independent fixture evidence for the v3 Release and C
sanitizer cases, not a scanner result.

The exact managed stdout and its `stderr`, `job_id`, `exit_code`,
`started_at`, and `ended_at` files were copied without deleting the
original job files to
`/qualification/r05-binary-oracle-20260929/` on the qualification bind
mount. The retained `oracle-result.jsonl` SHA-256 is
`1c275047d0090cc1fcc84434500ce00e4ede4bd5bc032ee9be389e7efa838b62`,
equal to the original managed stdout checksum. A separate read-only parse
required one JSON row with all expected content, materialization and
literal fields, the exact job ID, exit code zero, and empty stderr; it
passed. The managed timestamps were Unix seconds 1790641597–1790641667.

An earlier 7,755-byte tool version was separately transferred and passed as
managed job `job_b8c31c0edcde4959adcd925b56347c4e`, but omitted the
first-hole offset from its JSON. The second version above supersedes that
output while leaving both remote scripts and job records intact. The v3
ClamAV source package predates this new helper; the helper is bound by its
own checksum and must be included in the next immutable candidate package.
This receipt does not close the missing materialized 32-GiB-plus-one,
parser-family, stream, service, fanotify, production-CVD, or final readiness
cases. No usage reset, GitHub workflow action, commit, or push occurred.
