# Task receipt: Sonic1 current-source build and scanner smoke tests

Task ID / parent milestone: `R03` / roadmap Linux x86-64 development
qualification path

Scope: build the checksum-verified current checkout in the available Sonic1
x86-64 Docker environment and exercise the resulting scanner with bounded
clean and detection smoke tests. This receipt records development evidence
only; it does not promote a capability to release-qualified.

Canonical source:

- checkout: `/tmp/clamav-32gb-current-20260911`
- source archive SHA-256:
  `0e05b85322a35be6b107e6a70b4dcbd38701220acd63b5ab0ba8ce6846a5c321`
- the initial archive was checksum-verified before the disposable test-only
  repairs. The final remote qualification source was independently hashed as
  `ec9cc08768a7ef576c101bc4997f7a7055141c2654cb4cb889de4cee2539b007`; the
  current local working-tree file is
  `7a4a006b8ae486747efda5b4f81df86b8559a73c4200ac1bdb586782efed5028`
- the remote source was checked for the exact qualification assertion and
  timeout edits before its final build; its disposable-source hash should not
  be treated as a replacement for the local working-tree identity
- representative current-source hashes also matched the local checkout for
  `libclamav/scanners.c`, `libclamav_rust/onenote_parser/src/reader.rs`, and
  `docs/32gb-luna-execution-roadmap.md`
- Docker image: `clamav-32gb:dev-current`
- target architecture: Linux x86-64
- Rust toolchain: `cargo 1.97.1 (c980f4866 2026-06-30)`

The CMake configuration completed with Unix Makefiles and the roadmap test
flags enabled:

```text
-DCMAKE_BUILD_TYPE=Release
-DENABLE_TESTS=ON
-DENABLE_STATIC_LIB=ON
-DENABLE_SHARED_LIB=ON
-DENABLE_LARGE_FILE_DEFAULTS=ON
-DENABLE_LARGE_FILE_QUALIFICATION_TEST=ON
-DENABLE_MILTER=ON
-DENABLE_CLAMONACC=ON
-DENABLE_SYSTEMD=OFF
-DENABLE_MAN_PAGES=OFF
-DENABLE_DOXYGEN=OFF
```

The locked Rust dependency set was fetched into a persistent remote build
cache because the image did not contain the Git source for `clam-sigutil`.
The subsequent build was performed with `CARGO_NET_OFFLINE=true` and
completed successfully. The built artifacts included:

- `clamscan/clamscan`, reporting `ClamAV 1.5.3-largefile-devel`
- `x86_64-unknown-linux-gnu/release/libclamav_rust.a`, 58,329,544 bytes
- `clamscan/clamscan` SHA-256:
  `f4e54a1482d4325c05ac5467c4b8606d959cbd3dfbbbd1af8343ce67a33337df`
- `libclamav_rust.a` SHA-256:
  `50b0e2e7fc92c5449a354e44db3e9068edad37a38e7846bd18aedbf18ef6c1d0`

The workflow-equivalent static test build initially exposed four TFLite test
objects registered before their `START_TEST` definitions. The local test
source now declares those Check objects before registration. The TFLite
reference mutation fixture also had one incorrect padding offset (`412`);
the actual OperatorCode `builtin_code` field is at `416`, and the fixture now
mutates that field.

## Focused production-linked tests

The static-linked `check_clamav` target built successfully after those
test-target repairs. With the repository CVD trust root supplied through
`CVD_CERTS_DIR`, the current-source focused cases passed:

- `required_unsupported`: **47 checks, 0 failures, 0 errors**
- `onenote`: **2 checks, 0 failures, 0 errors**
- `rust_onenote`: **2 checks, 0 failures, 0 errors**
- `cryptff`: **3 checks, 0 failures, 0 errors**
- `gif`: **16 checks, 0 failures, 0 errors**

## Bounded scanner smoke tests

The unit-test CVD trust root was supplied through
`/candidate/unit_tests/input/signing/verify`, matching the CMake test
environment.
Bytecode was disabled for these small tests so the results exercised the
scanner and signature paths without requiring production CVD assets.

- clean scan of `README.md` with `unit_tests/input/clamav.hdb`: **passed**;
  `/candidate/README.md: OK`, exit 0
- temporary NDB signature scan of a generated test string: **passed**;
  `Test.CurrentSource.UNOFFICIAL FOUND`, expected scanner exit 1
- runtime linkage resolved `libclamav.so.14`, OpenSSL 3, and json-c

## Limits of this receipt

This is current-source Linux x86-64 Docker development evidence, not the
certified runner, sanitizer, full-size 32-GiB, production-CVD, daemon/service,
or final-canary evidence required by the roadmap. The release-readiness
snapshot therefore remains blocked at `597` total, `0` qualified, `143`
bounded, `440` pending, `14` allowlisted unsupported, `0` unsupported
required, and `583` blockers. No capability was promoted.

No local host software was installed. No GitHub workflow action, commit, or
push was used.

State: `development-verified`; release readiness remains blocked.

## Follow-on static-link, fixture, and scan-API revalidation

The first full `cl_scan_api` run exposed a test-target linkage defect rather
than a scanner defect: 24 encrypted-RAR checks were reaching the shared
`libclamav.so` path without the static UnRAR implementation, and the large
MHTML streaming case exceeded Check's short default timeout. The current
source was corrected and rebuilt as follows:

- `unit_tests/CMakeLists.txt` no longer links `check_clamav` through the
  shared `ClamAV::common` target. It adds the required `common/` include path
  and directly compiles `actions.c`, `misc.c`, `output.c`, `optparser.c`, and
  `getopt.c`, while retaining the static `libclamav` test link.
- `libclamav/CMakeLists.txt` now defines `UNRAR_LINKED` privately for
  `clamav_static`, matching its existing static UnRAR interface link without
  changing the shared-library dynamic-loader path.
- `unit_tests/check_clamav.c` gives the `cl_scan_api` case group a truthful
  60-second default budget for its 64-MiB-plus streaming fixtures; the `T`
  environment variable remains an explicit override.

The complete encrypted-fixture aggregate produced all 53 expected test
inputs. The static target rebuilt successfully, and the final binary
(`17e206be1168166e52179c536994ad167cb674bbac9644d1a6c8a07ecb528371`) has no
`libclamav.so` dependency in `ldd` output. With `CVD_CERTS_DIR` set to the
unit-test trust root at `/candidate/unit_tests/input/signing/verify`, the
default-timeout run completed:

- `cl_scan_api`: **836 checks, 0 failures, 0 errors**, including encrypted
  RAR and MHTML streaming coverage
- `required_unsupported`: **47 checks, 0 failures, 0 errors**
- `onenote`: **2 checks, 0 failures, 0 errors**
- `rust_onenote`: **2 checks, 0 failures, 0 errors**
- `cryptff`: **3 checks, 0 failures, 0 errors**
- `gif`: **16 checks, 0 failures, 0 errors**

This remains development evidence on Sonic1's Linux x86-64 Docker runner. It
does not establish certified, sanitizer, full-size 32-GiB, production-CVD,
daemon/service, R04 acceptance-record, or final-canary evidence. No
capability was promoted; release readiness remains blocked.

## Full current-source Check-suite revalidation

The rebuilt static `check_clamav` binary was re-run across the complete
`cl_suite` after materializing the AutoIt fixtures and applying the 60-second
default timeout to both large API test groups. The first rerun used the wrong
container path (`/candidate/certs`) and reported one CVD verification failure;
that was a test-harness trust-store selection error, not a CVD implementation
failure. The corrected run used
`CVD_CERTS_DIR=/candidate/unit_tests/input/signing/verify` and completed:

- `cl_suite`: **2,889 checks, 0 failures, 0 errors**
- static `check_clamav` SHA-256:
  `17e206be1168166e52179c536994ad167cb674bbac9644d1a6c8a07ecb528371`
- remote job: `job_ced63a28731e4578a0755364bb3bbdbb`

This confirms the current-source unit suite, including the strict malformed
CVD archive case, with the repository's intended test trust store. It remains
development evidence only; no capability was promoted and certified,
sanitizer, full-size 32-GiB, production-service, R04-record, and final
qualification remain open.

## Repository consistency gates

After the source-guard assertions were synchronized with the reader-backed
OneNote implementation, the local repository gates completed successfully:

- `sh tools/largefile_source_guards.sh` — passed; all 597 capability checks,
  release-readiness self-tests, acceptance-record schemas, and evidence
  checks passed.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — passed.
- `python3 -B tools/largefile_status_snapshot_test.py` — 13 tests passed.
- `git diff --check` and shell syntax checks — passed.

The generated `docs/largefile-inventory.tsv` was refreshed from the current
source tree before the guard run. No capability was promoted; release
readiness remains blocked pending the roadmap's certified, full-size,
production-service, and final-canary evidence.

## CTest control revalidation after repair

The configured large-file CTest controls were run against the disposable
Sonic1 build after the initial control run exposed three contract mismatches.
The repairs were test/build-harness scoped and preserved the fail-closed
roadmap expectations:

- `largefile_runtime_evidence_check`: **passed**, 9.80 seconds. The verifier
  now performs a bounded Python ELF64/x86-64 header check when a minimal build
  container has no `file` utility; it still rejects non-ELF, wrong-width, and
  wrong-architecture scanner artifacts.
- `largefile_clamscan_admission`: **passed**, 0.12 seconds. The fixture now
  explicitly uses `--alert-exceeds-max=no`, so it verifies the operational
  `CL_EMAXSIZE`/CLI exit-2 limit result rather than the optional alert-enabled
  detection-style exit-1 result.
- `largefile_library_exact_32g`: **passed**, 346.02 seconds. All three
  `cl_scanfile_ex2`, `cl_scandesc_ex2`, and `cl_scanmap_ex2` paths reached the
  exact tail marker and passed with the strong-indicator verdict, the exact
  unofficial alert, native 64-bit root size, and complete structured report
  accounting. The Check case uses a 900-second default timeout because the
  three sparse 32-GiB passes are intentionally CPU-intensive.

The two quick controls passed together as `2/2`; the exact control passed as
`1/1` under CTest. The final static Check binary SHA-256 was
`fc7fd546c89c55a4ced07e061eaa645e999adeb5009fafa2e9cfa91bce419f69`.
Remote jobs: `job_50bdc661122f4eada83a81f01409b83b` for the quick controls and
`job_b0f155cd793d4145bcbc621b85040c56` for the exact CTest control. No
capability was promoted; certified-runner, sanitizer, production-service,
R04-record, and final-canary evidence remain open.

## Fresh C ASan/UBSan revalidation after harness repair

A fresh `RelWithDebInfo` C AddressSanitizer/UndefinedBehaviorSanitizer build
was configured from the disposable Sonic1 source mount with the same
large-file, static/shared, milter, on-access, and test options as the Release
candidate. The build completed with exit 0 in container
`clamav-c-asan-build-current-20260911`. Its scanner dynamic section requires
both `libasan.so.8` and `libubsan.so.1`.

The first full sanitizer run found a real test-harness defect before test
execution: `tc_largefile` was conditionally declared but not initialized, and
ASan reported the invalid `tcase_set_timeout` write. The declaration is now
initialized to `NULL`; the corrected test target rebuilt with exit 0. The
initial run also exposed runner-layout omissions rather than code failures:
the tracked HDB fixture was not present at the CMake-embedded `/src` path and
the generated AutoIt fixtures had not been materialized. The exact tracked HDB
hash was restored and `tgt_largefile_autoit_fixtures` completed with exit 0.

With the source mounted at `/src` and generated inputs present, the focused
controls passed: `cl_api` **518/518**, `autoit_map` **9/9**, and
`autoit_corpus` **1/1**, all with zero failures/errors. The configured
`ctest -R '^libclamav$' --output-on-failure` run then passed **1/1** in
**132.17 seconds**. Its retained Check logs contained no
`AddressSanitizer`, `UndefinedBehaviorSanitizer`, or `runtime error:`
diagnostic. The scanner ELF has `libasan.so.8` and `libubsan.so.1` in its
dynamic dependencies.

Final sanitizer artifact hashes:

- source `unit_tests/check_clamav.c` in the remote disposable mount:
  `4a81f43c0caf099034398171ec731e969801c4a69e387820dcdc1a48f855fb36`
- current local working-tree `unit_tests/check_clamav.c`:
  `307b81d2e00225ef60bceb4041dfa4536598136974ec8561f3aa90cf8294ea6b`
- `clamscan`: `150a6d1dd065856076930d7454e293c9664ac499d5acc74cd82dd74b147fe2f8`
- `clamd`: `8d5d2a897cf5bf2bcbc03d6100a478484291b6a2309aeb4fe33e44b3c1ba1b31`
- `clamdscan`: `4b93624eaecf33e330beea2dc6e4e74ca8f0af46d544f54f9bdca5aae6dace8c`
- `check_clamav`: `55dea3dc6c7686c4fa6c08257d6038722d201291e8e4791901a7a4c06bf684b7`
- `check_clamd`: `7ef2b1bebe4d6351d3b7898a4b6b9827c864d5c4e88b6666263d7326bfd722d1`

The remote disposable source file and local working-tree file hashes differ,
so this is fresh sanitizer development evidence, not revision-bound final
qualification. Rust was built with the stable toolchain and was not
address-instrumented; the roadmap's Rust sanitizer requirement, certified
runner identity, full-size materialized acceptance matrix, production
databases, service/on-access evidence, R04 records, and final canary remain
open. No capability was promoted and release readiness remains blocked.
