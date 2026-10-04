# R08 Sonic1 v16 UDF unrecorded-sector development — 2026-09-29

This is a source-bound Linux x86-64 **development** build and focused parser
regression, not full-size parser, sanitizer, service, or release qualification.

## Source and build identity

The current dirty canonical tree was frozen as a deterministic Git-less source
package at `/private/tmp/clamav-udf-v16-20260929.tar.gz` (17,929,210 bytes,
SHA-256 `6893159391b2dbaf061f2252733a431c36e80e3f4b04128870e30347fd1178a2`).
Its source-content manifest SHA-256 is
`c49dee21a965a0fd78189c5465b36821c19dfeeca7dc02b09a070ea5365db530`.
MCP-SSH durable transfer `transfer_e1bf668a1158442c97f24c437cef544e`
committed by atomic rename after the expected size and SHA-256 matched. The
package was extracted in the pinned Sonic1 container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
as `/qualification/source-udf-v16-20260929`. The extracted provenance
manifest retained the above SHA-256, and `sha256sum --check --quiet` passed
both before and after the build.

Using the pinned v15 Linux compiler configuration as a development check,
`-fsyntax-only` succeeded for the v16 `libclamav/udf.c` shared and static
variants and for `unit_tests/check_clamav.c`. A separate Release CMake tree at
`/qualification/build-udf-v16-20260929-release` was then configured with
tests, shared and static libraries, large-file defaults and qualification
option, UnRAR, milter, clamonacc, and WERROR enabled. Its
`CLAMAV_SOURCE_COMMIT` and `CLAMAV_SOURCE_MANIFEST_SHA256` both equal the v16
manifest above. The successful managed build job
`job_444a7e11560b43329be36c85685a48ac` exited 0 after building
`check_clamav`; its full log is retained on the dedicated volume as
`build-check-clamav-20260929T1832.log` (SHA-256
`09c709b6e97075d25ee45eb3ad20dd4bdf424d8977561d4b8da0130936742a12`).

| Build artifact | SHA-256 |
| --- | --- |
| `unit_tests/check_clamav` | `02918e451193a4ce7c3bc71671081e7e26adccaacc622f745d967daab3ec5f8c` |
| `libclamav/libclamav_static.a` | `55da764b87bc81bf5d07dc7542e4fcce7ace8a3efd2f8fc59baa3b93978735ba` |
| `CMakeCache.txt` | `ab1a8b456ff47cb996adc9403b67b15a86f19d5d18c981b42a8af2f41ada59b5` |
| `compile_commands.json` | `e615f1da39f2491a14a4cb9086936ab1cde37ff2a545f487a3ca906d996442d2` |

The first two build attempts failed before testing the changed code: inherited
Rustup attempted to write its root-owned update temp directory, then inherited
`CARGO_HOME=/src/build` had no cached Git dependency. The successful run used
the *already installed* stable Rust toolchain and existing `/build/cargo`
cache with `CARGO_NET_OFFLINE=true`. No software was installed or downloaded.

## Focused UDF result

[ECMA-167 section 3/8.4.2](https://ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf)
permits an unrecorded sector to terminate a populated Volume Descriptor
Sequence extent. The v16 anchored UDF path accepts only an all-zero sector
for that terminator. A partially nonzero zero-tag sector remains malformed;
a wholly blank *main* extent still selects reserve as in v15. The registered
`udf_corpus` case now verifies late child-marker detection through the
unrecorded terminator and exact parse-incomplete/cache-tainted rejection for
its nonzero negative control.

`check_clamav` was run from its v16 build directory with `TMPDIR` on the
dedicated qualification volume:

| `CK_RUN_CASE` | Result | Retained `test.log` SHA-256 | Retained `test-stderr.log` SHA-256 |
| --- | --- | --- | --- |
| `udf_corpus` | 1/1, exit 0 | `9bf4f3e190505ec16edfb0b729fc7d2df8fd648bbcc38eadd018355831241dfd` | `a83013bd1ac571216df95f24a006ed9afbd7ae6af0c71f7e7e1ca061204fb546` |
| `udf_map` | 14/14, exit 0 | `79f3e68fd418d6c46a3663d6053632210ad2d99efd90d3b0bca77e185dff733b` | `9178602809ebfdbcb45b9283a42fef747ef15035eb719d6615921823cf18bc2f` |
| `required_unsupported` | 61/61, exit 0 | `a86d2a27a002bb204a13b8a5de70049c8bec0defc43288d113553c3f7f293aae` | `4302fef2a97790b711eaa776761433fc656a60ccb2fcac37c8a8aeb08a3e1e9f` |

Each row's logs were copied under distinct `test-<case>-20260929T18xx.log`
and `test-stderr-<case>-20260929T18xx.log` names in the v16 build's
`unit_tests` directory before starting the next case. These focused cases
do not substitute for the broad suite or complete UDF corpus.

After this build and focused testing, the dedicated qualification LV had
859,848,704 bytes available, the root overlay about 7 MiB, and `/dev/shm`
about 1.87 GiB. None meets the >=68-GiB free disk-backed staging or >=48-GiB
effective-memory qualification admission. The old 32-GiB tmpfs OneNote
fixture has a separately documented one-bit content mismatch and remains
untouched. No full-size or broad unit run was attempted from this v16 build.

State: `v16-source-bound-linux-development-tests-passed; full-qualification-pending`

## Application build and bounded smoke

The same v16 build, source, installed toolchain, and offline Cargo cache also
built `clamscan` and `sigtool` in managed job
`job_f82188f17ac94d36a91b1b5249a479ce` (exit 0). The retained
`build-apps-20260929T1835.log` SHA-256 is
`edad41c80291dfd03983e1c156d1dde033dec565ab4445c69953b65a38969f2c`.
`clamscan/clamscan` SHA-256 is
`276979ede0756c6a57546fe36f7704c0a8a0f15969700804a6838298d4b9e006`;
`sigtool/sigtool` SHA-256 is
`77ed75061b9c4692091b1fc95e535b13fda4309a23570b92616c92f6229aee9d`.

Both applications initially rejected their default missing *installation*
certificate directory `/usr/local/etc/certs`. Passing the already packaged
source certificate directory explicitly with
`--cvdcertsdir=/qualification/source-udf-v16-20260929/certs` resolved that
development-run setup error; no certificate installation or trust check was
bypassed. With the exact 544-byte decoded `clam.exe` control (SHA-256
`71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495`)
and packaged `clamav.hdb` (SHA-256
`e9649d9d3416df7802567063f88d8ff181795ed4e2bab827134c1707375df38c`),
`clamscan` reported `ClamAV-Test-File.UNOFFICIAL FOUND` with the expected
virus exit code 1. The same invocation on the packaged `README.md` reported
`OK` with exit 0. `sigtool --fuzzy-img` on packaged `logo.png` returned
`logo.png: af2ad01ed42993c7` with exit 0, matching the earlier v13/v15
control. These are small development controls, not production-CVD or
materialized-large-file qualification. Afterward the dedicated LV had
806,412,288 bytes available.

## Ordinary-suite environment and disk-floor diagnostic

A later non-qualification `cl_suite` attempt deliberately left
`CLAMAV_LARGEFILE_QUALIFY` and `CLAMAV_FMAP_REGRESSION` unset, used the v16
binary above, directed `TMPDIR` to the dedicated LV, and ran under a managed
300-MiB free-space watchdog. Its initial run lacked the CTest-required
`CVD_CERTS_DIR` environment; `cl_engine_new()` therefore selected missing
`/usr/local/etc/certs`. It finished in 53 seconds with 2,392 checks and
851 failures, dominated by database-load/setup failures. Two AutoIt tests
also lacked their generated fixtures because the targeted `check_clamav`
build does not build the separate `ALL` fixture target. This is **invalid
infrastructure evidence**, not a code-regression or full-suite result.
Retained artifacts under the v16 build's `unit_tests` directory:

| Artifact | SHA-256 |
| --- | --- |
| `test-cl-suite-missing-certs-20260929T1840.log` | `25df325509aeeb8b225783b4fb85ba1326c073ed58a5c146f9976e793f4e5c98` |
| `test-stderr-cl-suite-missing-certs-20260929T1840.log` | `db206f19b3c4fae84d299f7821b6e6ac65ee820fdbcb0a42b2b4ac47854177da` |
| `cl-suite-v16-20260929T1840.stdout.log` | `cf233295861edaa01ba24d547fa0f5fa5db5f765f56e5179176d8d447fe5d188` |

The next run set `CVD_CERTS_DIR` to the source's normal `certs` directory.
That fixed database-load setup and reached 1,097 passing checks. It also
revealed that this is *not* the test CVD signing directory: the one observed
failure was `test_cl_cvdverify` rejecting `test-1.cvd` because its dedicated
test-signing issuer was absent. CMake's authoritative unit-test environment
sets `CVD_CERTS_DIR` to
`/qualification/source-udf-v16-20260929/unit_tests/input/signing/verify`.
Before this suite could finish, its watchdog observed free space below
300 MiB and terminated the test process group; managed job
`job_1af06727fbf3469e9aa2b2a336175f46` returned watchdog exit 75,
`test_exit=-15`, and 242,708,480 free bytes. There is **no completed
suite verdict**. The partial logs were preserved before any later focused
test:

| Artifact | SHA-256 |
| --- | --- |
| `test-cl-suite-certs-disk-floor-20260929T1844.log` | `01f95dda56ee12745ae2c8f1529e1c8740e1c827ef61ffced3df83b31446537c` |
| `test-stderr-cl-suite-certs-disk-floor-20260929T1844.log` | `2696f74aafb363b0eab3d07d51b0558ab50253ec26318a83252fc55f3eee57af` |
| `cl-suite-v16-certs-20260929T1844.stdout.log` | `3877c58f5ed2483048ec978639517067b68e6039c7e0f99159b2489dfbd66970` |

The terminated run left no `check_clamav` test process, but retained
temporary files and logs remain untouched. No further broad suite run is
safe on this volume until capacity is expanded. The root overlay remained
separate and nearly full, rather than being used for test temporary files.

The missing AutoIt fixture target `tgt_largefile_autoit_fixtures` was then
built in the v16 tree (exit 0); its exact generated files are 85, 95, and
131,235 bytes. With the CTest-selected signing-cert directory,
`autoit_map` passed 10/10 and `autoit_corpus` passed 1/1, including the
previously missing positive controls. Their retained log pairs have SHA-256
`0ed75f869984ccfd17d40f40ff808b7bc926f1130da6ed90c54eb8762cb07b95` /
`a48eaf86528f029662b4746c22088615401fdd37efe02ced352368eadb9c6c10`
and `90692dacddedb14153a06470c1e097e6a30f92c13864f0eea8330d34f6a137a5` /
`edb9684e0b66ec4353a206c689cac74c24fe46856b4b89f5c0e8cc494db6cf59`
respectively. Finally, v16 `sigtool --verify` with those same test-signing
certs authenticated `test-1.cvd` and its `.sign` file (exit 0, signer
`ClamAV TEST CVD Signing Cert`). This isolates the earlier CVD assertion to
an incorrect development-run certificate path; it does not replace a
completed broad unit suite or the production CVD canary. The dedicated LV
had 242,446,336 bytes available after these focused runs.

Next broad run: expand the dedicated LV with user approval, complete the
fixture targets, use the CMake/CTest-defined environment, and retain its
full terminal result and logs. Do not retry the same broad workload on the
current nearly full volume.

## Post-v16 canonical-source change

The source-bound v16 build remains frozen at manifest
`c49dee21a965a0fd78189c5465b36821c19dfeeca7dc02b09a070ea5365db530`.
After the above diagnostics, the canonical checkout gained a narrow CMake
dependency from `check_clamav` to `tgt_largefile_autoit_fixtures`, plus a
source guard for that dependency. This prevents a *future targeted* unit
build from omitting the three fixture files its registered cases read. The
source guards passed (604 capability rows; acceptance-record schema passed
with 0 supplied records), and
`git diff --check` passed. The resulting current source-content manifest
SHA-256 is
`230d00333f48ae308640ca8812a3ce9fd968d958430b87b375fccffd4af95e01`.
It is **not** the v16 binary's source identity; this post-v16 CMake edit
has not yet been configured or rebuilt on Sonic1. A fresh package/build and
the full unit suite are required after provisioning, without reusing v16
results as current-source or release evidence.
