# R03 Sonic1 clean-candidate C ASan/UBSan exact qualification slice — 2026-09-21

## Scope and provenance

This receipt records fresh C AddressSanitizer/UndefinedBehaviorSanitizer
evidence for the current transferred candidate. It covers the full configured
CTest control matrix and the materialized exact 32-GiB library case. It does
not promote capabilities or claim Rust address-sanitizer instrumentation,
production-CVD readiness, privileged fanotify qualification, or final release
readiness.

- Branch: `largefile-roadmap-qualification`.
- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`.
- Source archive: `clamav-candidate-clean-5798545b.tar.gz`.
- Source archive SHA-256: `599c78070d0b745f23dc30476f3c564e68a0f1f8a35ae403ca18c95a95ef5f84`.
- Durable transfer: `transfer_22f567da4bad4db498156976272bf859`.
- Container: `f3bd2b0a7d1c975368d86f7f73898e9d08a2fd177e6e04dd58287607dfe43366`.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Host/profile: `sonic1` / `sonic1-camera-key`.
- Clean source: `/tmp/clamav-clean-5798545b`.
- Sanitizer build: `/build/sanitizer-clean-5798545b`.

The source archive was created with Apple metadata excluded. Its final remote
checksum matched the local checksum; the extracted candidate contained no
`.DS_Store` or `._*` source entries.

## Build and test configuration

The build used C and C++ `-fsanitize=address,undefined -fno-omit-frame-pointer`
compile/link flags, `RelWithDebInfo`, the large-file qualification options,
all application/library/test features required by the roadmap, and no systemd,
manual-page, or Doxygen dependencies. Tests used the cached stable Rust
toolchain with `CARGO_NET_OFFLINE=true` because the transferred `/src` mount is
read-only.

Rust nightly was not installed: the container provides only the stable
toolchain. Therefore this receipt records C ASan/UBSan coverage plus the
stable Rust functional tests, not Rust address-sanitizer evidence.

## Results

1. Non-exact sanitizer matrix, MCP-SSH job
   `job_ce72a29b5391404f82f3afe493e8f98d`: **32/32 passed**, exit 0, total
   test time 409.06 seconds. This includes `libclamav`, all large-file
   admission/resource/fail-closed controls, `clamscan`, `clamd`, `freshclam`,
   `sigtool`, examples, and the 161-test Rust functional suite.
2. Exact materialized 32-GiB library test, MCP-SSH job
   `job_3733e441ef7d41a7a1c2e46da4282d8a`: **1/1 passed**, exit 0, total test
   time 646.88 seconds. The test exercised the exact
   `34359738368`-byte boundary under the C sanitizer build.

No ASan, UBSan, leak, OOM, or swap diagnostic was emitted by either run. The
exact test process remained CPU-bound with low RSS during execution; the
materialized test completed rather than being shortened to a sparse or
sub-boundary fixture.

## Boundary and next work

This closes the current C sanitizer and exact-size development evidence slice.
It does not satisfy the final readiness gate because the current snapshot still
has pending capability-specific rows and requires independently bound cases,
full ingress/parser coverage, measured PCRE/resource phases, real fanotify
permission evidence, production CVD/service canary evidence, and Rust nightly
sanitizer parity. No capability was promoted and no GitHub workflow was
changed or triggered.

State: `development-verified; C-sanitizer-and-exact-size-passed; release-gates-open`
