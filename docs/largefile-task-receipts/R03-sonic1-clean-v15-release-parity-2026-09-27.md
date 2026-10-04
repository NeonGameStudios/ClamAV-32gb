# R03 Sonic1 clean v15 Release parity — 2026-09-27

Task ID / parent milestone: R03 — matching-source Linux x86-64 Release build and focused exact-edge runtime. This complements, but does not replace, `R03-sonic1-clean-v15-c-asan-exact-2026-09-27.md`.

Starting Git commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d` on `largefile-roadmap-qualification`, with a dirty working tree. The tested immutable v15 source manifest SHA-256 was `e5b0d36e0ac086aed6c0d9fe7037ef0c3ba1fb9fd6f2b3ac38a14891c4e4b04f`; the deterministic package SHA-256 was `45d1e6e67647e5fb68a9c6e60db9d4331392af1b2725416aff978db74d56369c`, committed by MCP-SSH transfer `transfer_78bfd4d3efcd4ecc9319ed16ee67748d` and extracted cleanly at `/qualification/src-v15-e5b0d36e`.

## Build identity and result

- Host/profile: `sonic1` / `sonic1-camera-key`; container ID `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`; image ID `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Clean build directory `/qualification/build-v15-e5b0d36e-release`. Configure job `job_90f5c4429c114c0eb4ab140964044cfb` and build job `job_17f5f81e2a884fa7a173bcb719f18cf4` both exited 0; the latter took 161 seconds. Cargo used the existing `/build/cargo` cache offline; no software was installed.
- `CMAKE_BUILD_TYPE=Release`; apps, clamonacc, milter, UnRAR, shared/static libraries, tests, large-file defaults, large-file qualification test, and Werror were configured ON. Configure reported systemd `not found` and the bytecode interpreter rather than JIT. The build cache recorded `CLAMAV_SOURCE_COMMIT` and `CLAMAV_SOURCE_MANIFEST_SHA256` as the same v15 source-manifest hash.
- Build cache SHA-256 `f221a8694c14dfe964dddaf33ca36dfc53b33d4074928f0990cf1289ad56559f`; `unit_tests/check_clamav` SHA-256 `97fb223fb857a6ce98b64a4d01e7f92965c9b909193af1e64cef7af69389a678`; `clamscan/clamscan` SHA-256 `5a4d6acdb1ebe06e750f68f82be66bb3af239c1dce74c91bdaecb66e249f88f8`.

## Root-temp failure and corrected test environment

The first non-exact CTest job `job_c09770504a1c420abb9e61d25ec5cc21` was **not** a pass. Its `libclamav` target failed 10 of 2,958 internal checks, including mail/MHTML spooling, with `CL_ETMPDIR`/temporary-directory errors. Container `/tmp` was on Sonic1's nearly full root overlay, which fell to 21,548 KiB free during the job. The supervised job was canceled to avoid filling the host. A verified orphaned container CTest PID 350627 survived the job cancellation and was separately sent SIGTERM; a follow-up `ps` confirmed it stopped. Four exact test-generated 64–65 MiB files were moved, not deleted, from root `/tmp` to `/qualification/retained-root-tmp-v15-release-20260927/`, restoring root headroom. This failed/canceled run is retained as diagnostic evidence, not qualification.

The successful reruns set `TMPDIR=/qualification/tmp-v15-release-tests-20260927`, a private directory on the dedicated ext4 qualification volume. ClamAV's `cli_gettmpdir()` honors that variable. Live `du` showed 621 MiB of test spools there during `libclamav`; no new large files appeared in root `/tmp`. Root free space remained about 278,816 KiB after the full-size run.

## Corrected Sonic1 results

- Isolated `libclamav` job `job_91fba8d6f3ae44098a27d2b4936d5ba3` exited 0: 1/1 CTest target passed in 80.35 seconds, covering its complete internal check collection.
- Remaining-suite job `job_54b40fdcc4fc41d7a62fcbe5c6baa077` exited 0: 30/30 CTest targets passed in 150.30 seconds, including source guards, Rust, `clamscan`, `clamd`, milter, freshclam, sigtool, and evidence checks. Together with the isolated `libclamav` rerun, the non-edge Release matrix was 31/31 on one source/build identity.
- The exact RAM fixture `/dev/shm/clamav32gb-edge-20260926.bin` was rechecked immediately before and after scanning: 34,359,738,368 bytes, 67,108,864 allocated 512-byte blocks, inode 2 and mtime 1790469049. The test checks the final marker, `SEEK_HOLE`, unchanged fixture metadata, and late detection/report/budget assertions through file-path, descriptor and fmap library APIs.
- Exact-edge job `job_396dff6017d043fa8ab361b384b37ee3` exited 0: `largefile_library_exact_32g` passed in 344.97 seconds with empty job stderr. A live container sample showed 38.68 GiB / 62.21 GiB memory and 100.31% CPU; this is a point-in-time sample, not peak-RSS evidence. `/proc/swaps` was empty before and after. The separate custom edge signature is not a production CVD canary.

## Qualification boundary

The clean v15 source now has matching Release and C ASan/UBSan build/suite/exact-library-edge passes on Sonic1. This does **not** prove Rust address instrumentation, final disk-backed service admission, production-CVD behavior, complete parser/ingress cases, PCRE phase RSS, bytecode JIT, systemd integration, or the capability-specific release matrix. After the run `/qualification` had 54,652,192 KiB free, below the required 68 GiB admission threshold, and Sonic1 root remained nearly full. No host volume was resized; no capability status or release readiness was promoted.

State: `matching-source Release and C ASan/UBSan focused exact library parity passed; broader R03/R04–R15 release qualification pending`.
