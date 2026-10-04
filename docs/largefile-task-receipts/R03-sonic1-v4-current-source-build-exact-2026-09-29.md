# R03 Sonic1 v4 source-bound builds and exact edge — 2026-09-29

## Frozen candidate and transfer

This receipt covers a fresh current-working-tree Linux x86-64 candidate,
not final release readiness. The deterministic source package is
`/private/tmp/clamav-yc-stream-20260929-v4-source.tar.gz` on the client,
17,905,665 bytes, SHA-256
`2efc584180e27b93bfcce704e9a29336353a951c2a36e04c13def7360c93eafe`.
Its embedded source-content manifest SHA-256 is
`1ab7e63f3b74eb987e2eef9b79a672e4fedab83bda83ed13c9895ad9bf8e1ff0`.
The package includes the new bounded binary-literal oracle, its eight
tests, and CTest registration. Local source guards passed, including the
604-capability map and source/readiness checks.

MCP-SSH transfer `transfer_1fa2dcffa4e94708b78b7b7e06d06a64`
accepted the raw 17,905,665 bytes by its configured handoff and committed
atomically at
`/tmp/clamav-qualification-disk-lv-v1/r13-v32-d2531599f754-mcp108/source-yc-stream-v4-20260929.tar.gz`.
Independent Sonic1 `sha256sum` matched the package SHA-256 above. The
archive was extracted to
`/qualification/source-yc-stream-v4-20260929` in the pinned qualification
container. Managed job `job_97066773947c4c7fb6a846fb63cd6db8`
regenerated the Git-less source manifest from extracted bytes and exited
zero; bytewise `cmp` matched the embedded manifest, and both hashed to
`1ab7e63f3b74eb987e2eef9b79a672e4fedab83bda83ed13c9895ad9bf8e1ff0`.

Sonic1 profile: `sonic1` / `sonic1-camera-key`. Pinned container ID:
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`;
image ID:
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Container provenance showed the expected read-only `/ram` fixture bind,
read-write `/qualification` bind, and running state before compilation.

## Builds and broad tests

The v4 Release configure/build jobs were
`job_08049d0040e14c2cabd9965715a0f603` and
`job_c02583c9e97b44ad8e2abc240a837de2`; the separate C ASan/UBSan
configure/build jobs were `job_fd1f9b514a9e4f8ea9e01de73baeac90`
and `job_e61cfb2834bc4f1ebd831b4479b6af67`. All four exited zero.
Both CMake caches bind `CLAMAV_SOURCE_COMMIT` and
`CLAMAV_SOURCE_MANIFEST_SHA256` to the exact manifest above. Required
application, clamonacc, milter, UnRAR, static/shared libraries, tests,
large-file defaults and qualification test toggles were requested ON,
with Werror. The C sanitizer build used GCC address/undefined sanitizers,
frame pointers, and sanitizer link flags. An independent inspection found
543 C/C++ compile commands and zero missing either sanitizer flag.

| Artifact | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `CMakeCache.txt` | `b29ca3126d65244e58d8afc9e7920daeb51a011ab4e44c9f24e5f38f73ef1f79` | `732733843a582eccbb5debdedb971e0f6dcdc4d386d9383085902d2cd19a9c8e` |
| `clamscan` | `064be4e7f5b9b3d8f65c2ea09d12d28babb288fb98f7b435a350fc1a575a8479` | `37e6cf687ff2984aafc3f2abbf113d04fa6d6f48d72498bf6fce42620f1e48c2` |
| `unit_tests/check_clamav` | `23c2f74e5e859fe993395eb8b24ce2ec498a78bb4e4c0ab810c977a773ca978f` | `7ec93d0cdacbabff7e253373ecef9c4f595d034ada21bcd0a63cd26c296eb69f` |

The separate non-edge CTest jobs
`job_5fc4ec472d9a4fb4b4f3b0c16ce9557c` (Release) and
`job_3436d6b4ecf94eab9756a3671f5053c2` (C ASan/UBSan)
each passed **32/32**, in 240.86 and 423.30 seconds respectively.
They included the new `largefile_binary_literal_oracle` test, library,
Rust functional, clamscan, clamd, milter, freshclam, sigtool, source
guards and evidence controls. The C sanitizer run set
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`; neither CTest job
captured stderr. Their test scratch trees remain retained and are not
claimed empty.

## Separate fully materialized exact-32-GiB library case

The read-only `/ram/edge-stable.bin` fixture was independently rehashed
by the bounded oracle in
`R05-sonic1-bounded-binary-oracle-2026-09-29.md`: exactly
34,359,738,368 bytes, SHA-256
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`,
fully allocated with the first hole at EOF and one independently located
marker at EOF−16. `stat` before and after these runs preserved
67,108,880 allocated 512-byte blocks, inode 8149459, and mtime 1790047133.

The dedicated Release CTest job `job_22b9614f15f246aa8da17d512ac2dcd8`
passed **1/1** `largefile_library_exact_32g` in 426.76 seconds. The
dedicated C ASan/UBSan job `job_8bd3eb335dfd44839d1a785446f39de7`
passed **1/1** in 766.64 seconds, with leak detection and halt-on-error
settings. These tests exercise the current-source library path, fd and
fmap assertions, not every parser or ingress. Each case-private temporary
directory was empty afterward. The host OOM-kill counter stayed at the
pre-run value 47, the pinned container's `memory.events` remained
`oom=0, oom_kill=0`, and swap stayed disabled. This does not erase the
separately recorded earlier `grep` OOM diagnostic. Post-test qualification
volume free space was 36,279,736 KiB.

## Qualification boundary

This evidence verifies a coherent v4 Release and C-sanitizer build,
broad registered tests, and the exact-size library control. Stable Rust
1.97.1 is still used; linked sanitizer runtimes do **not** provide Rust
`-Zsanitizer=address` instrumentation. Configure requested systemd but
reported its development library absent, and the bytecode runtime is
interpreter-only. The 36-GiB free qualification volume is below the
separate 68-GiB disk-backed service admission, so no full service/on-access
run was claimed. Production CVDs, full ingress/parser/capability matrix,
PCRE phase proof on v4, privileged fanotify, final canary and release
readiness remain open. No software was installed, no usage reset was used,
and no GitHub workflow, commit, or push was performed.
