# Task receipt: five-issue hardening and verification

Task ID / parent milestone: `R00` / roadmap follow-up across `R03`, `R04`,
`R06`, `R09`, and `R10`

Exact capability areas exercised:

- `library:pdf-metadata-callback-context`
- `library:arj-header-status-declaration`
- `library:arj-open-read-status`
- `library:internal-declaration-egg`
- `library:internal-declaration-scan-report`
- `matcher:rust-fuzzy-image-ffi-admission`
- `matcher:fuzzy-image`

Starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`.
The canonical checkout is `<repository-root>`,
branch `largefile-roadmap-qualification`, with the pre-existing dirty working
tree preserved. The pre-receipt tracked-source manifest hash for this slice is
`c81db77ce9bd65b9fd5a45a1d74423595473d7e8aa7baab9d03e40bde25cbccd`.

## Changes made

`libclamav_rust/src/fuzzy_hash.rs` now uses fallible reservations for the
fuzzy-signature `HashMap` and each per-hash metadata vector before mutation.
An allocation failure returns `Error::Allocation` through the existing C
`FFIError` boundary instead of panicking in an extern function. A Rust
regression now loads two metadata records for one hash, exercising the shared
metadata-vector path. `tools/largefile_source_guards.sh` pins both the
fallible reservation and regression name. The capability description records
the new fail-visible allocation behavior.

## Focused production-linked development checks

The existing ARM64 production-linked Check binary was run inside a disposable
Docker container with the repository test CA supplied through
`CVD_CERTS_DIR`:

- `CK_RUN_CASE=pdf`: **24 checks, 0 failures, 0 errors**
- `CK_RUN_CASE=arj_map`: **8 checks, 0 failures, 0 errors**
- `CK_RUN_CASE=egg_map`: **12 checks, 0 failures, 0 errors**
- `CK_RUN_CASE=cl_callback_api`: **4 checks, 0 failures, 0 errors**
- `CK_RUN_CASE=gif`: **16 checks, 0 failures, 0 errors**

The binary used for those five focused groups is the retained current-source
development binary with SHA-256
`2f10f60f5a9a097bfe918cbfcfe1cdcfa27aeebe97996035867d787a4cf6cd91`.
It predates the final Rust-only allocation edit because the copied CMake graph
cannot relink without absent development artifacts (`libcheck_pic.a` and
related linker files). Therefore the new Rust edit is source-guarded but not
claimed as compiled by this exact binary.

## Repository controls

- `sh tools/largefile_source_guards.sh` — **passed**; 597 capability rows and
  all acceptance controls passed.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed;
  2 expected skips**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- `git diff --check` — **passed**.
- `sh tools/largefile_release_readiness.sh --status` — **exit 1 as expected**:
  597 total, 0 qualified, 143 bounded, 440 pending, 14 allowlisted
  unsupported, 0 unsupported required, and 583 blockers.

## Prerequisite and boundary notes

The disposable container installed `libsubunit0`, `libjson-c5`, and
`ninja-build` only to inspect/run the existing ARM64 development test tree;
nothing was installed on the host. The attempted relink remains blocked by
missing CMake development artifacts, and a Rust-only offline check remains
blocked by the uncached `clam-sigutil` dependency. No certified Linux x86-64,
sanitizer, production-CVD/service, full-size, materialized-edge, or final
canary evidence was produced. No capability status was promoted.

No remote execution, remote SSH, usage reset, banked reset, GitHub workflow
action, commit, or push was performed.

State: `development-verified` for the five focused issue areas; release
qualification remains blocked.
