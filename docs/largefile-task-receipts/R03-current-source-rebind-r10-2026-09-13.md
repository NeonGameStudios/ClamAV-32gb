# R03 current-source control rebind — 2026-09-13

## Source and builds

- Source manifest: 1,697 entries,
  `4ff6260cf89396c0d4a5c96c889b89558cab599e33c4b26976921ce629749efc`.
- Existing ARM64 Docker container: `clamav-current-rust-build-20260911`.
- Release cache: `/tmp/clamav-release-current-20260913`,
  `85e4b359d664e953c8b8e795a33d5f39d442a46efb97da0f9a0d864bf584d79c`.
- ASan/UBSan cache: `/tmp/clamav-asan-current-20260912`,
  `86efe63172ecc6de3b9c551d935429bda3292b3aca19de353e4d39d4f6cee92f`.
- Release `check_clamav`: `395d236f58f664a2cd8bbe8718e3e1e14fc4c563d2764024ae32f75c0581f067`.
- ASan/UBSan `check_clamav`: `3e5346b491693581b7a76ceaa6a4df8d0a32fde860802a80c9eea00074f46d3e`.

Both trees reconfigured and built successfully; no software was installed.

## Verification

- Release CTest excluding only aggregate `libclamav`: **27/27 passed** in
  129.13 seconds.
- ASan/UBSan CTest excluding only aggregate `libclamav`: **27/27 passed** in
  518.44 seconds, with no sanitizer diagnostics.
- Host large-file harness: **174 passed**, 2 Linux-only allocation tests
  skipped on macOS.
- `git diff --check`, status snapshot freshness, and source guards passed.

The complete aggregate ASan/UBSan `libclamav` target was not rerun after
these Python-only evidence-consumer changes. Its latest same-container
diagnostic is recorded in `R03-current-source-rebind-r09-2026-09-13.md` as a
1,200-second timeout without sanitizer diagnostics; it remains incomplete,
not a pass. No capability was promoted.
