# R06 current-source nested OneNote spool-budget propagation

Date: 2026-09-13 UTC

## Scope

This receipt covers the R06 hardening slice that opens OneStore header and
object-property payloads through ReaderBlob::open_reader_with_spool_options.
Nested parser readers now retain the originating private-spool directory and
the shared BlobSpoolBudget, so binary items discovered inside a spooled
object-group payload remain under the same temporary-storage contract.

The change is deliberately narrow: compatibility APIs that explicitly
materialize bounded property or embedded-file data remain unchanged, and no
capability row was promoted.

## Source identity

- Source manifest: 1,697 entries; SHA-256
  e1fd11451db8e3537aa404f38367ea3affff2e31cf551d15449c9454d839586d
- libclamav_rust/onenote_parser/src/reader.rs SHA-256
  9d51540e4620c6601c64347fb04c3d5d842e324126c3b165dcd2cf588735247c
- git diff --check: passed
- Source inventory regeneration diff: clean

## Test environment

- Disposable container: clamav-current-rust-build-20260911
- Image: rust:1.97-bookworm
- Architecture: ARM64
- Source mount: repository mounted at /src
- No software was installed for this receipt.

## Parser and Release evidence

- Locked offline parser unit suite: 79/79 passed.
- Release check_clamav rebuilt successfully.
- Release cache SHA-256:
  af2fe69b889f05d0ab5b6b87d1bb742873825371d8226e6a414275a74c08d959
- Release unit_tests/check_clamav SHA-256:
  90bae44794bbeb3999a142d2acce134b066590473ba9eac36bee1724b15293ee
- Release configuration: Release, APP/MILTER/TESTS/UNRAR enabled,
  large-file defaults off, qualification off.
- Full configured Release CTest:
  ctest --test-dir /tmp/clamav-release-current-20260913 --output-on-failure
  passed 28/28 in 199.01 seconds.

## ASan/UBSan evidence

- Sanitizer cache SHA-256:
  342f477d96232ca059ff9cee3bfe052fcfa584e216ee4b229fb83fc15dd43e25
- Sanitizer unit_tests/check_clamav SHA-256:
  a3612742d9e5b1abcc5a04d60f91439f4d61798367186fd7799c503b846707da
- Configuration: RelWithDebInfo, C/C++ flags
  -fsanitize=address,undefined -fno-omit-frame-pointer, APP/MILTER/TESTS/UNRAR
  enabled.
- Bounded sanitizer CTest:
  ctest --test-dir /tmp/clamav-asan-current-20260912 --output-on-failure -E libclamav
  passed 27/27 in 533.65 seconds.
- Retained LastTest.log SHA-256:
  514e0f3205ef642590f32820972f7c322bf1b20251f2af750530ac09bcda1dc5
- Sanitizer log scan found no AddressSanitizer, LeakSanitizer,
  UndefinedBehaviorSanitizer, or runtime error: diagnostics.
- The aggregate libclamav sanitizer target remains explicitly excluded and
  incomplete under the established ARM64 duration limit; this receipt does
  not claim an aggregate sanitizer pass.

## Qualification status

This is ARM64 development evidence only. Certified Linux x86-64, exact or
materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1,
independent format-8, and final release evidence remain open. No capability
was promoted.
