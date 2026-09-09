# Task receipt: current-source Linux x86-64 Docker build and application tests

Task IDs / parent milestones: `R03` / `R10`

Scope: build the canonical current checkout as a coherent Linux x86-64
development candidate and run the complete discovered CTest application suite.
This is reproducible current-source development evidence; it is not the
roadmap's certified 32-GiB qualification or sanitizer candidate.

Canonical source and build identity:

- source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- branch: `largefile-roadmap-qualification`
- HEAD at capture: `41cde8160286813f0f98e109c1450e40ff4117fb`
- working tree intentionally dirty; the build used the actual current source
  bytes and retained the generated source-manifest hash below
- source mounted read-only at `/src` inside the disposable container
- build output: `/private/tmp/clamav-32gb-current-target/cmake-release`
- container: `clamav-32gb-rust-build-amd64-20260909`
- image: `rust:1.97-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97`
- platform: `linux/amd64`; kernel: `6.12.76-linuxkit`

Toolchain:

- GCC `12.2.0`
- CMake `3.25.1`
- Rust/Cargo `1.97.1`

Configure profile:

- Release build with shared and static libraries
- application, tests, milter, clamonacc and UnRAR enabled
- interpreter bytecode runtime
- large-file defaults disabled; qualification option disabled
- CTest temporary root set to `/tmp/clamav-cmake-test` inside the container

Results:

- coherent CMake build: `100% Built target check_clamav`
- serial CTest: `16/16` passed, total test time `508.27` seconds
- passed entries include Rust, clamscan, clamd/`check_clamd`, freshclam,
  sigtool, milter protocol/quota, R04 capture, source guards, runtime
  evidence, and large-file admission/report controls
- `check_clamd`: 111 checks, zero failures and zero errors
- the earlier parallel-2 run exposed resource contention between the
  exhaustive source guard and daemon stress test; the daemon passes in
  isolation and the complete serial suite is green
- local tools suite: 145 tests passed, 2 expected skips
- service evidence verifier regression passed
- acceptance map and record schema checks passed
- `git diff --check` passed

Retained artifact hashes:

- `libclamav_rust.a`: `f90fbf444bc59b2a03e59a9181f2ea4f57f6db6cbbeb349e20b15d9b1e30b657`
- `clamd`: `f0b2db9142c0b58d7de30aaec3c7818786ef6f9ea3729afcf7a736ef3602bfe5`
- `clamdscan`: `25ab44b82205f278bbaf14ff650fbdf357ba8d211fd9f225ddf9fa90faf9957a`
- `clamscan`: `0f5eb8516cfc911e42d55c2aa47f3e62102be45cdcb37be4b7467fe26d6040f7`
- `check_clamd`: `ef5b34b7ed9f69e5158d51656a0b0fc84a7cdbdd23ef1d8a02b349e50945a53d`
- `clamav-milter`: `854007fe3af739ac4713f09cb054b3e7e7872239cbcbd2ae1891e92059780a57`
- `CMakeCache.txt`: `c379d7693d3e238939d81991d8de39a95d8d876d4fe214ba17b959fbcb5db494`
- `compile_commands.json`: `76df92a7f0e9925992a7b0268120dfd021048635a8a161c061008e6aa577e096`
- `source-manifest.txt`: `8167c2002d1191b2f9f1e4bb9e7e7bf5f7972f90f20f6ad53497d74d9eadfffd`

Boundaries:

- The container reports approximately `1.77 GiB` available memory, while
  exact-edge admission requires the roadmap's `48 GiB` minimum and the full
  32-GiB materialized workload requires more. No exact-edge qualification was
  claimed from this environment.
- The Rust artifact is a normal Release build, not the required nightly
  address-instrumented Rust candidate.
- R06's modern OneNote reader remains blocked on a dependency API that accepts
  a bounded reader rather than an entire `&[u8]`; R09's seven required rows
  remain unresolved pending implementation or an explicit user-approved
  contract change.
- Readiness remains `0` qualified, `143` bounded, `440` pending, `14`
  unsupported, and `583` blocked. No capability was promoted.

No commit, push, GitHub workflow action, usage reset, or banked reset was
performed. Linux build packages were installed only inside the disposable
Docker container; no host Linux sysroot was installed.
