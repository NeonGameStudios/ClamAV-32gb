# R08 CVD TAR finalization and sigtool slice

Task ID / parent milestone: R08 / CVD archive production and sigtool behavior

Exact capability kind:id list: library:production-cvd-ingress; library:production-cvd-api-boundary

Starting commit and working-tree/source manifest identity: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`; working tree intentionally dirty with the roadmap candidate changes. The active checkout is `/Volumes/512gbNVME/github-external/ClamAV-32gb` on `largefile-roadmap-qualification`.

Observed failing case and expected behavior: strict CVD loading correctly rejected archives without the two TAR end blocks, but sigtool and freshclam archive writers did not emit those blocks. Sigtool's unsigned CVD fixtures also needed to retain historical `DSIG:` text for cdiff matching while unsigned loading ignored that metadata. The expected behavior is marker-complete generated archives, strict signed verification unchanged, and explicit unsigned metadata handling.

Changes made: added shared `tar_finish()` finalization to emit both required zero blocks and wired it into sigtool and freshclam archive creation. Updated unsigned `.info` parsing to stop at an embedded `DSIG:` record instead of treating it as a database entry; signed verification still hashes and verifies the record. The CVD numeric-header parser now accepts the fixed-width space padding used by valid FreshClam range responses while still rejecting non-numeric trailing data. The sigtool and freshclam tests now generate deterministic marker-complete fixtures with writable members, isolate diff fixtures from build inputs, and preserve the isolated build signature-count contract. The clamd test now covers the existing fail-closed limit fixtures, while the daemon promotes only named `Heuristics.Limits.Exceeded.*` alerts to FOUND under `AlertExceedsMax`. The inventory tool now has a deterministic Python fallback when `rg` is unavailable, and the committed inventory was regenerated from current sources.

Commands and results:

- Disposable ARM64 `cmake --build /tmp/clamav-largefile-static-build --target sigtool -j2`: exit 0.
- Disposable ARM64 `cmake --build /tmp/clamav-largefile-static-build --target check_clamav -j2`: exit 0.
- Deterministic CTest subset (`libclamav`, fail-closed POC, source guards, runtime evidence, milter quota, Rust, clamscan, sigtool): 8/8 passed; retained at `/private/tmp/clamav-largefile-static-build/ctest-final.log`.
- Direct `CK_RUN_SUITE=cl_suite CK_DEFAULT_TIMEOUT=300 .../check_clamav`: 2,271 checks, 0 failures, 0 errors.
- Full direct `freshclam_test.py`: 11 tests, 0 failures, 1 platform skip; both strict-CVD full-download fallback cases pass with runtime-generated, signed marker-complete fixtures.
- Full direct `clamd_test.py` with container-local `TMP`: 15 tests, 0 failures, 0 errors; the socket test was run inside the container because the host-mounted filesystem cannot create the required Unix socket.
- Disposable ARM64 `cmake --build /tmp/clamav-largefile-static-build --target check_clamav -j2`: exit 0.
- `git diff --check`: exit 0.
- `sh tools/largefile_release_readiness.sh --status`: 597 total; 0 qualified, 143 bounded, 440 pending, 14 unsupported; `release_readiness=blocked`.

Development tests passed: current-source archive-writer, unsigned CVD metadata, sigtool cdiff/build, source-guard, inventory, Rust, clamscan, milter quota, and runtime-evidence gates.

Full-size/certified evidence produced, or explicitly not run: no certified Linux x86-64 run, sanitizer qualification, full-size 32-GiB ingress run, production CVD corpus, daemon qualification, Sonic1 resource evidence, or GitHub workflow action. The unfiltered aggregate CTest wrapper remains environment-limited on ARM64 even though the direct roadmap `cl_suite` run passes.

Remaining failures / next slice: release readiness remains blocked by the unavailable certified x86-64 runner, required R04/R10–R15 evidence, R06 modern OneNote reader-backed API, R07 format-8 compiler/artifact, and remaining R09 in-scope rows. No capability is promoted to qualified release status by this receipt.

State: development-verified
