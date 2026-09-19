# Current-source Sonic1 rebuild and bounded controls — 2026-09-19

## Scope

This receipt records development evidence from the current local branch after synchronizing the changed C/C++/Rust sources into the existing Sonic1 ClamAV container. It covers source-guard portability, a focused rebuild, and three bounded regression controls.

This is not a release qualification record. It does not establish the full R04/R06/R09 qualification gates, full Release/sanitizer coverage, materialized 32-GiB storage behavior, or final R11/R12/R13/R14/R15 readiness.

## Local source

- Repository: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- Branch: `largefile-roadmap-qualification`
- HEAD: `aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe`
- Inventory: 45,575 lines; SHA256 `782b36d13ba2fac0515f6b885c224160939728a0973c32fd769b3e4a692177d0`

## Sonic1 execution identity

- Host: `sonic1`
- Login profile: `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Source bind: `/tmp/clamav-32gb-7f3458c4` mounted at `/src`

The synchronized current-source files were `libclamav/mbox.c`, `libclamav_rust/onenote_parser/src/reader.rs`, and `unit_tests/check_clamav.c`. The local inventory and the generated remote inventory matched byte-for-byte and by SHA256. A disposable synthetic Git ref was created inside the container only so the snapshot checker could read the local HEAD; it is not independent Git provenance and is not used as qualification evidence.

## Results

1. Source guards passed (`job_7d760c563e334940942462a26e248b9c`):

   ```text
   large-file capability manifest passed (604 entries)
   large-file release readiness tests passed
   large-file acceptance record schema passed (14 records)
   large-file acceptance case map passed (604 capabilities)
   large-file acceptance record schema passed (0 records)
   large-file source guards passed
   ```

2. Focused `check_clamav` rebuild passed (`job_2e1df866680d450b88fe2ed282e2f726`). The rebuilt binary included the current `mbox.c`, OneNote reader, and `check_clamav.c` sources and completed at 100%.

3. Public API regression passed (`job_f90d3119492c4be7a11d15630a95b1df`): 533 checks, 0 failures, 0 errors.

4. Logical 32-GiB fmap traversal passed (`job_cd61b588d2304f07b133a645fc32a8f2`): 1 check, 0 failures, 0 errors. This exercised the logical 32-GiB traversal control; it did not materialize a 32-GiB test file.

5. Required-unsupported behavior passed (`job_6206f645258f498aafa032ca7715c032`): 61 checks, 0 failures, 0 errors.

## Interpretation

The current synchronized source builds and passes the bounded API, logical-fmap, and required-unsupported controls on Sonic1. The result advances development confidence for the touched source and R03/R06/R09 control paths, but release readiness remains blocked by the roadmap status gates and the separately recorded hardware/toolchain constraints.
