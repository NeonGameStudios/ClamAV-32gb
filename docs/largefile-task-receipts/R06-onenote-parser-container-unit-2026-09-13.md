# Task receipt: R06 current-source OneNote parser crate tests

Task ID / parent milestone: `R06` / `R03`

## Exact scope

Run the Rust `onenote_parser` crate's own unit, integration, and doc-test
targets against the current source mounted at `/src` in the retained
`clamav-current-rust-build-20260911` container. This supplements, but does
not replace, the production-linked C FFI and scanner checks.

## Provenance

- host worktree: `/Volumes/512gbNVME/github-external/ClamAV-32gb`;
- branch: `largefile-roadmap-qualification`;
- starting HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db`;
- container source mount: current worktree at `/src`;
- source manifest: 1,697 entries;
- source manifest SHA-256: `ea89582cd812e7147eb7c5ac06f4c98e54c6103bbc801384dc0c8fb08eb0cbd2`;
- Rust toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`;
- test binary SHA-256: `7d40dff2191db4bedbfe7b9bd69c004e728c0a02f7357500c82f65159422e516`;
- configuration: Cargo test profile, `--offline`, package `onenote_parser`;
- the host did not install or download dependencies; the retained container
  supplied the already-cached `insta` dependency that is absent from the host
  cache.

## Command and result

```text
docker exec -w /src clamav-current-rust-build-20260911 \
  cargo test --offline -p onenote_parser
```

The command exited 0 and reported:

```text
library unit tests: 80 passed, 0 failed
integration tests:   5 passed, 0 failed
doc-tests:           0 passed, 1 ignored, 0 failed
```

The integration set includes the logical reader case whose input is above
the former whole-input cap, plus short-read/path-parser coverage. The run
completed without sanitizer diagnostics or test failures. Rust emitted
existing dead-code, lifetime-syntax, and Rust-2021-formatting warnings; no
warning was promoted to an error.

## Qualification boundary

This is current-source ARM64 development evidence. It does not establish
certified Linux x86-64, a materialized 32-GiB fixture, production-CVD/service,
resource/fanotify, Sonic1, independent format-8 bytecode, or final release
qualification. No capability status was promoted.

No usage reset was used, no software was installed, no branch/history/remote
was changed, and the retained container was stopped after the run.

State: development-verified
