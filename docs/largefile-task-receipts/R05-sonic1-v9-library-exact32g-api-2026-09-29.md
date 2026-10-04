# R05 Sonic1 v9 exact-32-GiB library API Release/C-sanitizer parity — 2026-09-29

## Scope and identity

The source-bound v9 Release build ran the registered
`largefile_library_exact_32g` CTest against the fully allocated
34,359,738,368-byte fixture. The source test checks regular-file allocation,
`SEEK_HOLE`, a marker at EOF minus 16, and exact virus/strong-indicator/report
and offset results from `cl_scanfile_ex2`, `cl_scandesc_ex2`, and
`cl_scanmap_ex2`. This is only those three modern library entry points, not
the full ingress or parser acceptance matrix.

Host/profile: `sonic1` / `sonic1-camera-key`. Container:
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`;
image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The v9 source package and independently regenerated manifest are described in
`R13-sonic1-v9-bounded-capture-race-2026-09-29.md`; the manifest SHA-256 is
`884ba2f7a7e180a063c48bb62a8417e20277dee9c849c2f8e307bfdc50fb06b0`.
The exact evidence root is
`/qualification/r05-v9-library-exact32g-20260929-release`. It contains a
copied source manifest, CMake cache and `check_clamav` binary with SHA-256
values `884ba2f7a7e180a063c48bb62a8417e20277dee9c849c2f8e307bfdc50fb06b0`,
`6e80757e0e72b8fba04529ea43d9324670bb4e0848dd368c1edc175fe25addf5`,
and `042ea7d984c3b67fe8d44b25629d0e52cd24e02ccdf66a55b0d142e9ba0f90e4`,
respectively. The resource sidecar binds those exact hashes.

The fixture `/ram/edge-stable.bin` is a read-only, host-ext4-backed bind, not
tmpfs. Pre- and post-run `stat` matched: size 34,359,738,368 bytes;
67,108,880 allocated 512-byte blocks; inode 8149459; mtime 1790047133.
The prior independent full-file SHA-256 oracle is
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
A new full-file post-run rehash, managed job
`job_cfb2bea399634556a129b31794fa438f`, exited 0 and returned exactly
the same SHA-256.

## Result and independent checks

Managed MCP-SSH job `job_fc9fafd6549e477bbad2b554a0dfbb3c` exited 0
after 618 seconds. CTest reports 1/1 passed in 617.20 seconds, zero failed.
The v9 resource wrapper retained 5,785 ordered process-tree samples. Its row
records 119,628/112,475 KiB RSS/PSS peaks, 8,192-byte sampled temporary
peak, and zero sampled swap, OOM events and OOM kills. The case-private
temporary directory was empty after the run.

A separate read-only verifier exited 0 after checking the test log outcome;
one and only one resource row; source, binary and cache file hashes against
the row; all consecutive sample sequences and strictly increasing timestamps;
a stable root PID present in every sampled PID set; PID counts and uniqueness;
root-versus-tree RSS ordering; row-versus-trace RSS peak equality; zero
swap/OOM; and empty temporary directory. It reported 5,785 verified samples,
peak RSS 119,628 KiB and root PID 1739754.

| Retained artifact under the evidence root | SHA-256 |
| --- | --- |
| `provenance/test.log` | `ee22033813553f5f0464438f7f4d6b48582382366ce4fe45a8a16c13825197e5` |
| `provenance/acceptance-case-resources.tsv` | `07880a1e6e38806e5e670358789bc9cd3aa6382b8d1b0b673d8f69632c907092` |
| `provenance/samples.tsv` | `c23b68779c63b200d7345e4aac0901397aaf8a171b17dffb49c256e68ebc6953` |

## C ASan/UBSan exact-size parity

The separate source-bound C sanitizer build and its 32/32 passing non-edge
CTest suite are described in
`R03-sonic1-v9-source-bound-builds-2026-09-29.md`. The C sanitizer exact-edge
evidence root is `/qualification/r05-v9-library-exact32g-20260929-asan`.
Its copied source manifest, `check_clamav` binary and CMake cache hash to
`884ba2f7a7e180a063c48bb62a8417e20277dee9c849c2f8e307bfdc50fb06b0`,
`f21297a2651c236de621f998c821f88eff5658d22b335e85ccd62c18a22facf7`
and `1d2be36a7087eed76c5a4c88ceb93997edda5a5c64c5f23330b0efe57c50e5b6`;
the resource row binds those exact hashes. The managed job
`job_cfb37f778001445eaaa28f201b8be321` used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`,
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`, a case-private temporary
directory and `T=1800`. It exited 0. CTest reports 1/1 passed in 1024.91
seconds; the inner Check log reports `Checks: 1, Failures: 0, Errors: 0`.

The wrapper retained 7,966 ordered process-tree samples. Its resource row
records RSS/PSS peaks 311,800/305,696 KiB, sampled temporary peak 8,192
bytes, zero swap, OOM events and OOM kills. The temporary directory was empty
afterward. An independent read-only verifier exited 0 after checking the
source/binary/cache hashes against the row, all sequence numbers and
monotonic timestamps, stable root PID membership and PID-set cardinality,
row-versus-trace RSS peak, CTest and inner Check outcome, zero swap/OOM,
empty temporary directory, and no AddressSanitizer, LeakSanitizer,
UndefinedBehaviorSanitizer or `runtime error:` diagnostic in retained test
logs. It reported 7,966 verified samples, 311,800-KiB peak RSS, and root
PID 1816946. Post-run fixture size, allocation, inode and mtime still matched
the Release preflight. A new full-file post-run rehash, managed job
`job_49aa840f611746e79f146e7d2bdf3121`, exited 0 and returned the same
independent SHA-256 oracle
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.

| C sanitizer retained artifact | SHA-256 |
| --- | --- |
| `provenance/test.log` | `7a93acc37474fb03d789ce5a5cfeac4ee600e98b7e36fb43aaf7e3c01d571ff1` |
| `provenance/acceptance-case-resources.tsv` | `2566a441ad45cae5c2ff3d851048c20b4a6bb149d8f5ff8cf3c4bf1eab09867a` |
| `provenance/samples.tsv` | `e8ae16a48d8c0e59ec73059e57d15adefcd15963de0303f99fd2fb274867788c` |

This gives current-v9 Release/C-sanitizer exact-size evidence for three
modern library APIs only. The C sanitizer build includes uninstrumented
stable Rust; this is not Rust address-sanitizer parity. Required clean, limit
and operational-failure cases for these APIs, other ingress modes, 32-GiB
OneNote deep parsing, production CVDs, PCRE memory phases, real fanotify and
final readiness remain open. No capability was promoted.

State: `v9-exact-three-api-release-and-c-asan-passed; post-run-fixture-sha-verified; release-gates-open`
