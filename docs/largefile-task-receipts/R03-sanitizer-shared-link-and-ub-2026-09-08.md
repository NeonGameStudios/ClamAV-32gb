# Task receipt: R03 shared-link and mixed-sanitizer closure

Task ID / parent milestone: `R03` / `R00`.

This receipt records disposable Docker development evidence only. It does not
promote a capability or replace the certified Linux x86-64, 64-GiB runner
required by the roadmap.

## Source and build identity

- Canonical checkout: `<repository-root>`.
- Branch: `largefile-roadmap-qualification`.
- Starting HEAD: `41cde8160286813f0f98e109c1450e40ff4117fb`.
- Pre-receipt dirty-source manifest SHA-256:
  `08eecfb27528d462d893864c6d57afd30dbe71bc28bdcc19d208cb6aeb99d936`.
- Disposable build tree: `<related-checkout>/.codex-builds/rust-asan-amd64`.
- Container: `rust:1.97-bookworm`, `linux/amd64` emulation, CMake
  `RelWithDebInfo`, static and shared libraries, examples, milter, and
  UnRAR enabled.
- C and C++ sanitizer flags:
  `-fsanitize=address,undefined -fno-omit-frame-pointer`.
- Rust sanitizer flags: nightly toolchain with
  `RUSTFLAGS=-Zsanitizer=address` and the generated Rust link argument for
  ASan/UBSan.

## Defects found and fixed

The workflow-equivalent shared build initially exposed an undefined reference
when linking `clamdscan`: the internal
`cli_scan_report_set_fallback_details()` symbol was used by the client but was
missing from the shared-library `CLAMAV_PRIVATE` version map. The symbol is now
exported at its intended private version.

The mixed C/Rust sanitizer test then exposed an LLVM ODR diagnostic caused by
GCC-emitted duplicate UDF switch tables. The UDF source receives
`-fno-jump-tables -fno-tree-switch-conversion` only when both C ASan and the
Rust nightly address sanitizer are active, leaving ordinary and production
builds unchanged.

The C UBSan pass found a real misaligned 64-bit store in bytecode global-array
initialization. All byte-buffer global writes in that path now use local,
correctly typed values copied with `memcpy`, preserving native byte order
without requiring alignment that the byte buffer does not promise.

## Verification

- Exact generated `libclamav` CTest target after the bytecode fix: **1/1
  passed**, 308.12 seconds, with `CK_FORK=no`, `CK_DEFAULT_TIMEOUT=300`,
  `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, and
  `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
- The rebuilt unit-test log contains 2,834 passing Check records. Its
  SHA-256 is
  `469e0fe3d084451f14f8d6e882c9907f086b2605e0e7b3931f62783a57036614`.
- The paired stderr log contains no `runtime error:`, AddressSanitizer,
  LeakSanitizer, or UndefinedBehaviorSanitizer diagnostic. Its SHA-256 is
  `f15811b45d52470fd3b2d0d041cd865acce6d6a277cf86874318f7ab8842727a`.
- Rust CTest in the same workflow-equivalent build: **152 passed, 0 failed**.
- The complete 17-target CTest run reached 65% overall. The Rust target,
  examples, freshclam, sigtool, milter quota, and large-file controls passed.
  Its remaining failures were retained as non-promoting diagnostics: the
  first C suite run contained the now-fixed UBSan store; source-guard and
  runtime-evidence tests exceeded their 60-second CTest budgets under
  emulation; daemon/milter admission correctly rejected the container's
  approximately 1.7-GiB memory against the 48-GiB requirement; and broad
  clamscan/clamd integration cases could not qualify in that constrained
  environment.
- The two slow control tests were then rerun through the regenerated CTest
  configuration after giving them a 300-second harness allowance. Both passed:
  `largefile_source_guards` in 204.70 seconds and
  `largefile_runtime_evidence_check` in 114.46 seconds, for 2/2 overall.
  The allowance changes only CTest scheduling; the assertions and release gate
  are unchanged.
- After inventory synchronization, `sh tools/largefile_source_guards.sh`
  passed with the 597-entry capability manifest, including all source,
  acceptance, runtime, fanotify, and PCRE controls.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` and `git diff --check` passed.
- A current disposable Docker capacity check reports `linux/x86_64`,
  `MemTotal=2467680 kB`, an unlimited cgroup memory value, and only
  `3548892` KiB free on the temporary overlay filesystem. This is far below
  the roadmap admission requirements of 48 GiB effective memory and 68 GiB
  free disk, so it is not an authorized qualification runner.

## Retained artifact hashes

- `check_clamav`: `94d196820b1b677374fedd1f93c2e28aad15ceab6cbdaf1af74bf934d8b39e0f`.
- `libclamav_static.a`:
  `70ea605d6e8100354d9cfaf0564d944d72f743fd78623df3e836d38874dc7206`.
- `libclamav.so.14.0.0`:
  `9792bbd545d313e51fee1058c84269eaea92fd4a66ee281036b70037283f0baf`.
- `CMakeCache.txt`:
  `e592ef54a45256d0420ada86038354ee68ae2aad801618f20d057683cc729232`.
- `compile_commands.json`:
  `7b242b253f0dcdf4eb4617a57bc6dbd9fa515b5804408620b230e45be6bcb62e`.
- Current post-regeneration CMake cache:
  `d43e486419296c840d6f232dbd32f5199bf0a3470a8783ac7dd7c418b457077d`.

## Limits and next action

No Sonic execution, MCP/SSH execution, host software installation, usage
reset, production CVD/service run, materialized 32-GiB case, certified Linux
x86-64 runner, or release qualification record was produced. Keep the affected
bytecode, shared-link, and sanitizer capabilities pending and repeat the full
matrix on the authorized 64-GiB Linux x86-64 runner.

State: `development-verified`; release readiness remains blocked.
