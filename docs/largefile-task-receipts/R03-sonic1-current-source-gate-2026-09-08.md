# Task receipt: Sonic1 current-source build gate

Task ID / parent milestone: `R03` / current-source Linux x86-64 qualification

Canonical local source:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- branch: `largefile-roadmap-qualification`
- local source remains intentionally dirty; no reset, clean, commit, push, or
  GitHub workflow action was performed

Remote identity:

- host: `sonic1`
- login profile: `sonic1-camera-key`
- kernel/architecture: `Linux sonic1 5.15.0-190-generic x86_64`
- existing build image: `clamav-32gb:dev-current`
- remote source root: `/tmp/clamav-32gb-runner-clean`
- remote build root: `/tmp/clamav-32gb-build-release`

Prerequisites verified:

- Sonic1 connection and profile authorization succeeded.
- The Rust-enabled derived image contains Cargo/rustc `1.97.1` and was built
  from the already authorized remote image/toolchain setup.
- The remote CMake configuration detects Release mode, shared library,
  UnRAR, milter, clamonacc, tests, large-file defaults, and the large-file
  qualification option.
- The previously synchronized unrar interface, milter source, lockfile, Rust
  build output, main library, regex, common, and `check_clamfi_quota` targets
  built successfully in the remote build tree.

Observed gaps and exact results:

1. Direct compilation of the remote `unit_tests/check_clamav.c` failed because
   the remote snapshot lacks these current declarations/tests:

   - `clamav_test_force_nsis_bzip_decoder_end`
   - `clamav_test_lzma_shutdown_calls`
   - `clamav_test_force_egg_lzma_decoder_init`
   - `test_cryptff_temporary_quota_is_fail_visible`
   - `test_cryptff_time_limit_is_fail_visible`
   - `test_cryptff_public_api_read_failure_is_fail_visible`

   The current local file is `2,466,846` bytes with SHA-256
   `2b5e416553b039d718d8a95e1abd3afa37e5ace6195823a7107128746a748b25`.

2. Reconfiguring the remote build with the certified feature set fails closed
   because the remote snapshot does not contain:

   - `/src/clamd/largefile_admission.c`
   - `/src/clamd/largefile_admission.h`

   CMake consequently cannot determine the link language for `check_clamd`.
   The current local admission source/header hashes are respectively
   `ddd5ba2079a2a8c8e6bdbebeadf21634a42cd6228725c7a5937e1db20f96c822` and
   `395b23187b02eee81709ca160c9fe88a6f01fca317ffef650ae737a351970984`.

3. The remote `check_clamd` target was attempted before reconfiguration and
   stopped without a build recipe because the generated graph was incomplete.
   No stale executable was substituted for current-source evidence.

Current local control revalidation:

- `sh tools/largefile_source_guards.sh`: exit `0`; capability manifest,
  readiness tests, acceptance schema/producer tests, fanotify and PCRE evidence
  controls, service controls, and source guards passed.
- `sh tools/largefile_release_readiness.sh --status`: exit `1` as expected;
  `597` total, `0` qualified, `143` bounded, `440` pending, `14` allowlisted
  unsupported, and `583` blockers.

Disposition:

- State: `blocked` for this remote current-source synchronization slice only.
- The durable transfer request for the specific current private source payload
  was rejected by MCP-SSH because payload-level authorization was not explicit
  enough. No workaround or indirect transfer was attempted.
- Once explicitly authorized, upload the current `unit_tests/check_clamav.c`
  and `clamd/largefile_admission.{c,h}`, regenerate the remote graph, and rerun
  the target-specific Release build. Until then, remote x86-64 qualification
  remains unproven; the local ARM64 evidence remains development-only.

No usage-reset or banked-reset tool was called. No host software was installed.

Independent clamscan slice on Sonic1:

- `cmake --build /build --target clamscan -j1`: exit `0`; the remote Release
  graph rebuilt `clamav`, `common`, Rust, regex, and the `clamscan` executable.
- `/build/clamscan/clamscan --version`: exit `0`, reporting
  `ClamAV 1.5.3-largefile-devel`.
- A clean scan of `/src/README.md` using the retained HDB test database and an
  ephemeral certificate directory returned `OK` with exit `0`.
- The repository NDB marker scan returned the exact
  `NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND` alert with exit `1`.
- A controlled `--max-filesize=1K --alert-exceeds-max` run returned exit `1`
  with `Heuristics.Limits.Exceeded.MaxFileSize FOUND` and the matching
  incomplete-scan warning.

These are genuine remote application smoke results for the independently
built clamscan target, but they do not qualify `clamd`, `clamdscan`, current
`check_clamav`, full-size materialized edges, sanitizer evidence, or release
readiness. The daemon target remains unavailable until the missing current
admission sources and test source are authorized for transfer.

Additional application-target build slice:

- `cmake --build /build --target clambc sigtool clamconf freshclam freshclam-bin
  -j1`: exit `0`.
- `clambc --version`, `sigtool --version`, and `clamconf --version` each exited
  `0` and reported `1.5.3-largefile-devel`.
- `freshclam --help` exited `0` and exposed the expected updater command
  surface. Its `--version` path requires an edited configuration file, so no
  false version claim was recorded.
- `clambc --version` reports `LLVM is not compiled or not linked`; this remote
  runner therefore provides interpreter/tooling evidence only and does not
  satisfy the roadmap's independent format-8 interpreter-plus-JIT requirement.

On-access client build slice:

- `cmake --build /build --target clamonacc -j1`: exit `0`; all client,
  communication, protocol, fanotify, queue, and scan-thread translation units
  compiled and linked.
- A direct `clamonacc --version` smoke invocation reached its configuration
  boundary and failed closed with `can't parse clamd configuration file` because
  the disposable image has no installed daemon configuration. No runtime or
  privileged fanotify claim was made from that invocation.

Client build slice:

- `cmake --build /build --target clamdscan -j1`: exit `0`; the current remote
  client, protocol, and report sources compiled and linked.
- `clamdscan --version` reached its required daemon-configuration boundary and
  failed closed because the disposable image has no installed `clamd.conf`.
  No client runtime or daemon-health claim was made without a freshly built
  daemon.

Milter quota control:

- Running `/build/unit_tests/check_clamfi_quota` in the Sonic1 Release image
  exited `0` with no diagnostic output, confirming the production-linked
  milter size/quota harness passes on the remote x86-64 toolchain.

Architecture control:

- `/build/unit_tests/check_fpu_endian` exists and returned exit code `2` with no
  output. The test contract defines `2` as little-endian FPU, which is the
  expected result for this x86-64 runner; the silent nonzero exit is therefore
  an expected architecture result, not a test failure.

Remote artifact identities captured after the executable slices:

- Docker image: `clamav-32gb@sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
  (`amd64`, `linux`).
- `CMakeCache.txt`: `eaff3f62f6cab4b9a138d54a467eaa4b153469bc0768dd5739fdbef1cac1dc55`.
- `compile_commands.json`: `f2f13b6a230cfc5677cadf94a511e470742ab154d23fe89c1d13dd8cc262b8e0`.
- `source-manifest.txt`: `ae775c7e8ab35d40d276d6e4131c566a7576d5673ac8372dfc6aea0a804d1c4e`.
- `libclamav.so`: `4f34b0ce1fc336d828fc1f6795761c74cb39e278f953fcf19d475d8d5db5bf2a`.
- `clamscan`: `2d0372baeafd7c37d6aec5a17d8338944259f4253d24de5ab71a96450a20e852`.
- `clamav-milter`: `945c2b7770687cf3c8bfd94ca4c7dcc153653aa4d9e914f9666ddb8a381d6c40`.
- `clamonacc`: `d81a17fe8974d472d5423cb0ce6e18cdffa1d26709b3e9273b25b3e288658644`.
- `clamdscan`: `493edab0750382ec7767b1a5e7cc1e3aef0b674e0a9874d94349b04d864f324a`.
- `clambc`: `69c5557e7ad4b56fe02484afb9089e904d8af60cdc2c333f3682dd225aacfb76`.
- `sigtool`: `a32ebd15951685e84da2101ebb8accb6050ea13c5905715e708936947bffe448`.
- `clamconf`: `4774de7d3af0481f687719530a68888f5fcc710ed480edeb2d756c59d297ed3a`.
- `freshclam`: `6b7d75a8f7cbc3f6df1d48aa85cfdc99ac35e957573398da4cc8e5e124c45a37`.

These identities describe a partial remote candidate only. They must not be
promoted to the final candidate until the missing current daemon sources are
present, the graph is regenerated successfully, and the full Release/sanitizer
and service matrix is rerun.

JIT prerequisite audit:

- Sonic1's complete existing Docker image inventory was checked. It contains
  the formatter-only image `ghcr.io/jidicula/clang-format:16`, but overriding
  its entrypoint to `llvm-config` returned `executable file not found in
  $PATH`.
- No existing LLVM development image or `llvm-config` tool was found, and no
  package/image installation was attempted. R07 remains interpreter-only on
  this runner until an authorized LLVM-capable environment is supplied.

Standalone sigtool behavior:

- `/build/sigtool/sigtool --md5 /src/README.md`: exit `0`, reporting
  `724a87476dd388a5102829311c738cec:5659:README.md`.
- The local canonical `README.md` independently reports the same MD5 and byte
  count (`724a87476dd388a5102829311c738cec`, `5659` bytes), binding the remote
  digest result to the expected input rather than accepting an unverified
  output string.

Application report-path probe:

- The rebuilt remote `clamscan` clean-scan path was exercised with
  `--gen-json=yes --debug --no-summary`; it exited `0`, emitted the expected
  `README.md: OK` verdict, initialized the engine in interpreter mode, loaded
  the test database, and produced bounded debug diagnostics.
- A follow-up probe passed `--report-json` to the same binary and requested a
  report file on a writable host-mounted temporary directory. The scan still
  exited `0`, but no report file was created. Passing an intentionally invalid
  report destination likewise exited `0` without a write error. This is
  additional evidence that the remote executable predates the current
  structured-report source slice; it is not evidence that the canonical
  report writer works. The current-source transfer and graph regeneration
  remain required before report-path or full application claims can be made.

Follow-on R03/R10 repaired-source Sonic1 service slice (2026-09-09 UTC):

- Host/profile: `sonic1` / `sonic1-camera-key` (`amd64`, Linux), using the
  retained `clamav-32gb:dev-current` image
  (`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`).
- An isolated source copy at
  `/tmp/clamav-32gb-runner-repaired-20260908` was made from the clean remote
  source and repaired with the retained `/tmp/clamav-extra-source.patch`.
  The patch command reported reversed/already-applied hunks for older slices,
  but applied the missing current `clamd/largefile_admission.c` and `.h` plus
  the applicable daemon/client sources. The current `unit_tests/check_clamav.c`
  was not transferred; this is therefore a repaired application slice, not a
  complete current-source qualification graph.
- Fresh configure succeeded in
  `/tmp/clamav-32gb-build-repaired-20260908` with Release mode, large-file
  defaults, qualification test support, clamonacc, milter, UnRAR, tests,
  shared-lib output, and interpreter bytecode runtime. The current repaired
  `clamscan`, `clamd`, and `clamdscan` targets each built with exit `0`.
  The `clamd` build explicitly compiled `largefile_admission.c`.
- Repaired-build identities: `CMakeCache.txt`
  `3bf9fc599e784e4fa082c6c3cd85bc9fad7aaeb4d57560411f2476462774e83c`,
  `compile_commands.json`
  `a6407e3843ca42ddc508d863facb7181f8fc8e037e64b493840eda3f01b94c66`,
  `clamscan`
  `d7013b541609a44103b08768e8ea71125929d4b577ab901fa6866568c734e07f`,
  `clamd`
  `088880e276773e4b491950ad40d02cb1fb5cc1c1c4f874f2e23905b351355713`,
  and `clamdscan`
  `493edab0750382ec7767b1a5e7cc1e3aef0b674e0a9874d94349b04d864f324a`.
- The daemon fixture needed an existing empty certificate directory mounted at
  `/tmp/clamav-empty-certs-20260908`; without that explicit prerequisite the
  current loader correctly failed closed before database admission. With it,
  the generated unsigned marker-complete CUD loaded successfully.
- A clean `clamscan` run against the CUD returned `README.md: OK`, exit `0`.
  A mixed daemon database containing that CUD and the canonical NDB test
  signature was then served by the freshly built daemon over an isolated TCP
  listener. `clamdscan` returned clean `README.md: OK`, exit `0`, and returned
  `NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND`, exit `1`, for
  `unit_tests/clamscan/allmatch_test.py`.
- The daemon/client detection report was written to
  `/tmp/clamdscan-repaired-mixed-detection-20260908.jsonl` with SHA-256
  `6cef51df528f684c2f330499b8f01dcf189424bcb8e82f5d6b0a1c46b7497913`.
  It records `status=1`, `verdict=2`, `completion=DETECTION_TERMINATED`,
  the exact alert `NDB.Clamav-Unit-Test-Signature.UNOFFICIAL`, and
  `last_alert_offset=5574`.
- A second isolated daemon configuration set `MaxFileSize 1K` and
  `AlertExceedsMax yes`. The same rebuilt client returned
  `Heuristics.Limits.Exceeded.MaxFileSize FOUND`, exit `1`, for the 5,659-byte
  README. Its report at
  `/tmp/clamdscan-repaired-limit-20260908.jsonl` has SHA-256
  `afdb74923156edd7e46d17edc84f1b6af91523adea66b69412b2f85a352dd990` and
  records `verdict=3`, `skipped_operations=1`, `max_file_size=1024`, and the
  exact limit reason. All isolated daemon containers were stopped after the
  checks.

This closes a genuine current repaired-source clamd/clamdscan service smoke
slice and supplies useful R04-bound clean, detection, and limit artifacts. It
does not qualify R03 or R10: the complete current `check_clamav` source was not
transferred, no certified full-size materialized run, C/Rust sanitizer run,
CTest matrix, production database, privileged fanotify run, or final canary
was performed, and the remote source graph still carries patch-bundle
provenance rather than a frozen immutable candidate. No host software was
installed, no usage reset was used, no commit or push was performed, and no
GitHub workflow was changed or triggered.

Development sanitizer slice (2026-09-09 UTC):

- A fresh isolated CMake build was configured in
  `/tmp/clamav-32gb-build-c-asan-ubsan-20260909` from the repaired source root
  `/tmp/clamav-32gb-runner-repaired-20260908` using the retained
  `clamav-32gb:dev-current` image. The configuration enabled
  `RelWithDebInfo`, C/C++ `-fsanitize=address,undefined` with frame pointers,
  large-file defaults, qualification-test support, tests, clamonacc, milter,
  UnRAR, shared libraries, interpreter bytecode, and the image's direct
  offline Cargo/rustc toolchain (`1.97.1`).
- The first build attempt correctly failed closed when the image's rustup
  proxy tried to sync the toolchain. Reconfiguring to the already-present
  direct Cargo/rustc binaries with `CARGO_NET_OFFLINE=true` resolved that
  environment issue without installing software or mutating the source.
- Named build container
  `clamav-c-asan-ubsan-build-retry-20260909` exited `0` after building
  `clamscan`, `clamd`, and `clamdscan`. The final link lines carried both
  `-fsanitize=address,undefined`; the outputs retained debug information and
  were not stripped. Artifact SHA-256 values were:
  `clamscan` `94d78d43aef43c628d2ba74548a69d50531a7e3dad2dd13588ef96a914032ed8`,
  `clamd` `1deb2f490d83c406f2827a56811d9be7e7961aa64da418ef13ef0f5561f1d354`,
  `clamdscan` `d2b94f078afd61fe2a7edd5729f1df786ba539967c8ac664998f172b6d2e4ec6`,
  and `libclamav.so.14.0.0`
  `56e4fa5b076bf6c9a3fd707c712c48854308655826c7f1da536508626899965c`.
- Named clean smoke container
  `clamav-c-asan-ubsan-smoke-clean-20260909` scanned a 1 MiB zero-filled
  input with the marker NDB and explicit empty certificate directory. It
  exited `0`, reported `OK`, scanned one file, and emitted no ASan/UBSan
  diagnostic.
- Named detection smoke container
  `clamav-c-asan-ubsan-smoke-detect-20260909` scanned a separate 1 MiB input
  containing the marker oracle. It exited `1` with the expected
  `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` result, scanned one file, and
  emitted no ASan/UBSan diagnostic.

This is valid development sanitizer evidence for the repaired application
targets. It remains non-qualifying until the complete current test source is
authorized and present, the frozen current-source graph is regenerated, and
the roadmap's full C/Rust sanitizer and service matrix is rerun against the
certified candidate.

Rust sanitizer dependency boundary:

- The retained Sonic1 image reports stable `rustc 1.97.1 (8bab26f4f
  2026-07-14)`, host `x86_64-unknown-linux-gnu`, LLVM `22.1.6`; no nightly
  suffix or alternate nightly toolchain is present in the authorized image.
- An isolated Rust-sanitizer configure attempt with `RUSTFLAGS=-Zsanitizer=address`
  and the direct offline Cargo/rustc paths failed at the repository's own
  `cmake/FindRust.cmake:500` guard: “Rust sanitizer support requires a
  nightly Rust toolchain because `-Zsanitizer` is unstable.” This is a
  concrete toolchain dependency, not a substituted C-only result.
- No Rust toolchain was installed or downloaded. R03 therefore has genuine C
  ASan/UBSan development evidence, while its required Rust address-instrumented
  artifact remains blocked on an authorized nightly Rust environment.

Sanitizer service smoke (2026-09-09 UTC):

- Named container `clamav-c-asan-ubsan-clamd-20260909` ran the freshly linked
  sanitizer `clamd` with the retained repaired configuration, an isolated
  combined database containing the repaired CUD plus the exact large-file NDB,
  and the explicit empty certificate directory. The daemon remained `running`
  after all probes and emitted no ASan/UBSan diagnostic.
- The freshly linked `clamdscan` clean request exited `0` with
  `/input-clean.bin: OK`; the marker request exited `1` with the exact
  `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` alert. `--ping=1` returned `PONG`.
- Retained structured reports were copied outside the container:
  `/tmp/clamdscan-c-asan-ubsan-clean-20260909.jsonl` has SHA-256
  `00ceb597d7dd745342aa19244c21a6cd15fa31b1da78258c4acd9eb9ac465496`, and
  `/tmp/clamdscan-c-asan-ubsan-detect-20260909.jsonl` has SHA-256
  `59d3e3de5236718638db3f3b354e1b0e7b9665a3712c85ff753429635e539b70`.
  The clean report records `status=0`, `verdict=0`, `completion=COMPLETE`,
  and `root_size=logical_bytes=1048576`; the detection report records
  `status=1`, `verdict=2`, `completion=DETECTION_TERMINATED`,
  `root_size=logical_bytes=1048576`, and `last_alert_offset=1048512`.

This extends development sanitizer evidence through the daemon/client ingress
and health path. It remains non-qualifying for R03/R10 until the complete
current-source test graph, nightly Rust artifact, certified source/build
identity, and full roadmap matrix are available.

Additional framed-stream ingress:

- The same named sanitizer daemon was exercised with `clamdscan --stream`.
  The clean request exited `0` with `OK`; the marker request exited `1` with
  the exact `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` alert.
- Retained stream reports have SHA-256
  `af1cd71326bdc156e6756dd2a95b23fe21cbbf94731b19b851f8af4317ad69e5`
  (clean) and
  `afa9baef6a4b3ac133023f2df1a7daa8daa5b0ab1cc36bc585b92a5e80a07306`
  (detection). The daemon was stopped after the probes; the named container
  and reports remain available for inspection.

Additional fd-passing ingress:

- A second named sanitizer daemon
  `clamav-c-asan-ubsan-fd-clamd-20260909` used a disposable copy of the
  retained configuration with `LocalSocket /tmp/clamd-c-asan-ubsan.sock`.
  `clamdscan --fdpass` returned clean exit `0`/`OK` for the clean input and
  detection exit `1` with the exact `LargeFile.POC.32g-edge.UNOFFICIAL FOUND`
  alert for the marker input.
- Retained fd-passing reports have SHA-256
  `2dcfa118da3d568221a9d10076f47570913760101bc8d97aba5ab7863bd94876`
  (clean) and
  `e9abe27cca392768c5396d34ff6a0014ba7d3f784267ec1ceefdaba78810f725`
  (detection). The daemon was stopped after the probes and the named
container remains available for inspection.

CTest source-graph boundary (2026-09-09 UTC):

- The existing C ASan/UBSan build registered 17 CTest entries. The bounded
  large-file subset was invoked from the generated `/build` path with the
  isolated repaired source mounted at `/src`.
- `largefile_poc_fail_closed` passed and
  `largefile_runtime_evidence_check` passed. The first two results are
  meaningful controls against the sanitizer build and did not emit a
  sanitizer diagnostic.
- `largefile_source_guards` failed immediately because the repaired remote
  source copy lacks the current `common/clamdcom.c` stream-call shape. The
  acceptance-schema, clamscan-admission, and clamd-report-protocol entries
  could not start because their current test files are absent from that
  partial source copy. CTest reported 2/6 passed and exit code 8.
- This run does not qualify or invalidate the local source. It identifies the
  exact prerequisite for the next Sonic1 attempt: transfer or otherwise
  authorize the complete current test/source graph, regenerate the build, and
  rerun the full CTest and service matrix. No unchanged retry was made.

Multiscan-stream sanitizer ingress (2026-09-09 UTC):

- The rebuilt sanitizer client advertises both `--multiscan` and `--stream`.
  With `--multiscan` alone, a client-only path correctly returned exit `2`
  (`Can't get file status`) because the daemon container could not see the
  client path. With `--multiscan --stream`, the clean input returned exit `0`
  and `OK`; the marker input returned exit `1` with the exact
  `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` alert.
- The clean report hash is
  `98de9afb1e38adc23d968c1216e800f812c5f8b0f217ae0437c24f160751a48a` and
  the detection report hash is
  `d1bd2bb0f2685bc84d27c38d5ebabc6ef4b44c318e7f87b392577914a4a884f7`.
  The reports bind `COMPLETE`/`DETECTION_TERMINATED`,
  `root_size=logical_bytes=1048576`, zero skipped operations, and detection
  offset `1048512`. The named daemon was stopped after the probes.
- This is development sanitizer evidence for the client mode combination,
  not certified or full-size qualification evidence.

Plain multiscan sanitizer ingress (2026-09-09 UTC):

- A path-visible control mounted each fixture at the same path in the
  `clamdscan` and `clamd` containers and exercised plain `--multiscan`.
  Clean returned exit `0`/`OK`; detection returned exit `1` with the exact
  `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` alert.
- The retained clean and detection report hashes are
  `b0be52182846c58bb70de0ad702954b486a66e9c32e2508c20f604457c101e47` and
  `be9f3a34e4adfe70dfb6904b768b625a314967af97da1cbdb22724bbd7ac9c12`.
  They bind `COMPLETE`/`DETECTION_TERMINATED`,
  `root_size=logical_bytes=1048576`, zero skipped operations, and detection
  offset `1048512`. The named daemon was stopped after capture.
- This is development sanitizer evidence only; it does not qualify the
  capability or the release gate.

Fdpass-plus-multiscan and startup cleanup follow-up (2026-09-09 UTC):

- The first disposable Unix-socket attempt stopped before application ingress
  because a fresh named socket volume was root-owned. The daemon reported
  `Permission denied` while binding the socket, and LeakSanitizer reported a
  2,313-byte engine-init leak on that startup-abort path. The volume was
  repaired in place and the probe was rerun; this finding led to a source
  cleanup change in `clamd/clamd.c`.
- With the disposable socket permissions corrected, `clamdscan --fdpass
  --multiscan` returned clean exit `0`/`OK` and detection exit `1` with the
  exact `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` alert. The retained report
  hashes are `0ccdc70a032d8f905527e257236608e0c9ec5f066977a89794853f21e70a0795`
  (clean) and `47beae9900b9e287f3b07de794801f0b1a100eee3ab34eebff2a741339279f79`
  (detection); the detection report binds `DETECTION_TERMINATED` and
  `last_alert_offset=1048512`.
- The successful daemon log contained no ASan, UBSan, or LeakSanitizer
  diagnostic. The local source now clears the engine ownership transfer after
  `recvloop()` and frees the engine on startup failure before that transfer.
  The remote sanitizer binary predates this source correction, so a post-fix
  sanitizer startup rerun remains required before treating the leak as closed.

This is development sanitizer evidence only. The complete current source/test
graph, Rust nightly artifact, certified source/build identity, and full-size
qualification matrix remain open.

Current-source rebuild boundary on Sonic1 (2026-09-09 UTC):

- A disposable Docker volume was initialized from the retained `clamav-32gb:dev-current`
  image and overlaid with the canonical checkout's current root/CMake files,
  Rust crate, daemon/common sources, source-manifest tool, and the headers
  required by the changed C translation units. The overlay SHA-256 values are
  `0a2f31b1ce57022329fd00debea22558970b3b3ea0a155493fb7cb600f69504d`
  (root), `22f7619732fe5dc3374b22ac7d8d494cb47f36c7dfa4e9cedfa8217d77a315ac`
  (Rust), `6ad35c458dff1dbe3158d9ebf45cb6b7ecf3da1e563a9afb7699d6946572129f`
  (daemon/common), `2eedcf5f1ea00524093fefb0a205c02f150360d669928594027a468d8dd230ef`
  (public headers), and
  `cb8face8fda142085e59a68e349135801303b7a66e0e554d7d6731d9077246a6`
  (unrar interface header). This is a development overlay, not a complete
  immutable source transfer.
- CMake configure completed successfully with the large-file defaults disabled,
  tests disabled, and the existing Sonic1 ARM64 dependency/toolchain set. The
  full build reached the Rust step but could not complete the locked dependency
  graph: offline Cargo reported missing `adler2 v2.0.1`, and a single bounded
  network-assisted Cargo attempt timed out before producing a build. A later
  offline check reported another absent locked crate, `android_system_properties
  v0.1.5`. No host software or Rust toolchain was installed.
- As a bounded source check independent of the incomplete Rust graph, the
  configured compiler successfully built the current `clamd/clamd.c`,
  `common/clamdcom.c`, and `clamdscan/client.c` translation units with zero
  diagnostics. This validates the R03 startup-engine ownership cleanup and
  the R10 daemon/client stream/report ingress changes at the C
  translation-unit level.

The current-source CMake configure and C-only checks pass on Sonic1, but the
complete Rust-linked application build remains blocked by the unavailable
locked dependency cache. This evidence does not qualify R03, R04, R06, R09,
or R10 and does not change capability status.

Targeted current-source relink boundary (2026-09-09 UTC):

- The retained Docker image `clamav-32gb:dev-current` exists with image ID
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
  The disposable `clamav-current-source-20260909` volume exposes valid CMake
  targets, but its build files are root-owned; the first unprivileged target
  invocation failed with exit 2 while writing a dependency file. Re-running
  the same target as container root advanced through the existing Rust target
  and rebuilt C objects.
- The CMake build then exposed the exact overlay boundary: the volume had no
  generated `clamav_rust.h`, so the existing header was mounted read-only from
  the retained Sonic1 build bind mount. Its SHA-256 is
  `fa88017207eea3dea79edf0523911139c6f5aa0a8b759ec254225a0e0db20739`.
  With that header available, the build reached `libclamav/fmap.c` and failed
  because the volume still contains an older declaration of
  `cl_fmap_set_hash(..., char)` while the overlaid current `clamav.h` declares
  `cl_fmap_set_hash(..., const unsigned char *)`.
- The canonical checkout's `libclamav/fmap.c` and `libclamav/clamav.h` agree;
  therefore this is not a newly discovered source defect. It proves that a
  full current-source application build needs a complete source overlay (or a
  fresh authorized transfer), not another partial header/object retry.

This targeted build remains development evidence only and does not qualify
R03 or promote any capability. No source-tree status changed.

Sonic1 source-volume provenance recheck (2026-09-09 UTC):

- The prior container that completed `clamd` and `clamdscan` exited successfully,
  but Docker provenance binds `/src` to
  `/tmp/clamav-32gb-runner-repaired-20260908`, not the canonical checkout or
  the current-source volume. Its binaries therefore remain historical
  development artifacts, not current-source proof.
- A read-only Git inspection of `clamav-current-source-20260909` shows a broad
  dirty transfer state, including deleted repository files and untracked
  AppleDouble `._*` artifacts. It is not a coherent source graph suitable for
  a release build. No new build was claimed from that volume, and the rejected
  private-source transfer was not retried.

The current-source build gate remains externally blocked by the need for a
complete authorized source/build environment and the unavailable locked Rust
dependency cache; no capability status changed.
