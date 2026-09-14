# R03 current-source Release and ASAN/UBSAN matrix strict-refresh — 2026-09-14

Task ID / parent milestone: `R03` / `R10`.

This receipt binds the bounded application/control revalidation after the
strict-warning cleanup of `disasm.c`, `filtering.c`, and related headers. The
current-source manifest contains 1,697 entries and has SHA-256
`5b64f7a13b71b0320aa5104d9c8f9bbc1e941a30c99bb62a612686e0fc8f0fe4`.

## Verification

Using the retained ARM64 `rust:1.97-bookworm` Docker container
(`clamav-current-rust-build-20260911`):

* The complete `ENABLE_WERROR=ON` application build passed with exit 0.
* The current-source Release build passed with exit 0. Its CMakeCache
  SHA-256 is `1645995e25859b5563715da91a714a90691f688c7b4645dc55aaec7fae32f615`.
* The current-source ASAN/UBSAN build passed with exit 0. Its CMakeCache
  SHA-256 is `ade9a74d0690bb89fe2f2e4a060af9be20339e9632c1d58da5c840ae46cdb460`.
* Release `cl_api` (`f3654b4006e248f6e95f6a0dd0a78fd16d8b764db7a4faf430b377895d1c288c`)
  passed 529/529. Focused Release and ASAN/UBSAN 7-Zip, YARA, and bundled
  regex cases passed with no sanitizer diagnostics.
* The bounded Release CTest matrix completed 26/27; the sole failure was
  `largefile_procfs_tree_rss`, where a short-lived sampler process disappeared
  between `/proc` reads. Rerunning that exact test passed, so all 27 bounded
  Release tests passed across the initial run plus the targeted retry.
* The ASAN/UBSAN bounded matrix passed through `clamscan` (24/27) and then the
  daemon test terminated the retained container with exit 137. This is an
  external container-resource boundary; the remaining daemon/freshclam/sigtool
  cases are not counted as passes for this run.
* An unfiltered Release `check_clamav` run reached 2,942 checks with five
  aggregate-only HTML/MSXML MaxFiles assertion failures. The affected HTML
  case and all four MSXML cases each pass when isolated; this is retained as a
  test-order/state-isolation issue, not relabelled as a clean aggregate.

This is ARM64 development evidence. It does not qualify any capability and
does not replace certified Linux x86-64, exact/materialized 32-GiB,
production-CVD/service, resource/fanotify, Sonic1, independent format-8, or
final release evidence. No software was installed, no usage reset was used,
and no commit, push, or GitHub workflow action was performed.

State: `development-verified; certified-and-aggregate-followup-pending`.
