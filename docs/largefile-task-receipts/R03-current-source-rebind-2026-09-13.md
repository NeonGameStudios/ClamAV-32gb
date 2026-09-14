# R03 current-source build rebind — 2026-09-13

Task ID / parent milestone: `R03` / `R01`, `R06`, `R09`.

The retained ARM64 Docker Release and ASan/UBSan build trees were reconfigured
and rebuilt after the working tree's roadmap and audit text changed. The prior
executables were treated as stale for current-source claims until this rebind.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`. The current Git-mode source
manifest contains 1,697 files and has SHA-256
`12aecbdf0c16bfae5aabb5480bb89554f6fcbd9e3ab77f6d2180ba43680e1f42`.

Build environment: existing `clamav-current-rust-build-20260911` Docker
container, `Linux-aarch64`, Rust 1.97.1, no software installation. Existing
trees were reused:

- Release: `/tmp/clamav-release-current-20260913`
- ASan/UBSan: `/tmp/clamav-asan-current-20260912`

Commands and exits:

- `cmake -S /src -B /tmp/clamav-release-current-20260913 -DCMAKE_BUILD_TYPE=Release` — exit 0.
- `cmake -S /src -B /tmp/clamav-asan-current-20260912 -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_ASAN=ON -DENABLE_UBSAN=ON` — exit 0.
- `cmake --build /tmp/clamav-release-current-20260913 -j2` — exit 0; all targets built.
- `cmake --build /tmp/clamav-asan-current-20260912 -j2` — exit 0; all targets built.

Retained identities:

- Release CMake cache: `d2c8b698107393f57d109a486b1a50d2d830a4f482b8393d97f216b58b646869`.
- ASan/UBSan CMake cache: `aebbead7f8e4cec19039ef1bf85e7740b9f28d142530a07a72e2d986b9b5fd94`.
- Release `clamscan`: `3a59979b9987600aaf9590cece8ac51bd9e508d99808a652a73c61d0c89c754b`.
- Release `check_clamav`: `395d236f58f664a2cd8bbe8718e3e1e14fc4c563d2764024ae32f75c0581f067`.
- ASan/UBSan `check_clamav`: `3e5346b491693581b7a76ceaa6a4df8d0a32fde860802a80c9eea00074f46d3e`.

Application and parser controls:

- Release `clamscan --version` reported `ClamAV 1.5.3-largefile-devel`.
- Release clean README scan with the repository test database and test CA — exit 0, `OK`.
- Release test ZIP scan with the same explicit database/CA — exit 1,
  `ClamAV-Test-File.UNOFFICIAL FOUND`.
- Release `rust_onenote` — 4/4 passed.
- Release `required_unsupported` — 57/57 passed.
- ASan/UBSan `rust_onenote` — 4/4 passed.
- ASan/UBSan `required_unsupported` — 57/57 passed.

The missing-default-database smoke was intentionally fail-closed with exit 2;
it was not counted as application success. The corrected smoke used explicit
repository test inputs. This remains ARM64 development evidence only: no
certified Linux x86-64, exact/materialized 32-GiB, production CVD/Sonic1,
resource, fanotify, or release qualification claim is made.

No capability was promoted. No usage reset, installation, commit, push,
workflow action, or remote mutation was performed.

State: `development-build-rebound; qualification-blocked-by-runner-and-fixtures`.
