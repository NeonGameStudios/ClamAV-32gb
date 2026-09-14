# R03 current-source build revalidation after protocol-test correction — 2026-09-13

Task ID / parent milestones: `R03`, `R10`, `R13`.

## Source identity

- Repository: `<repository-root>`
- Branch: `largefile-roadmap-qualification`
- Git base revision: `8e837b88c89874b180a1a25f22d287f7d6be29db`
- Working tree remains intentionally dirty; no commit, push, branch, or
  GitHub workflow action was performed.
- Current source manifest: 1,697 entries,
  `8bc6ca7cb824cfd13e3e6980a79d053503d9df9a475e6d90f23c0392f82aeb34`.

## Change covered

The structured-report path test helper now ignores `SIGPIPE` in its child
fixture. This keeps the expected negative case (the client closes after an
infected report has no alert) from being misreported as a child crash. The
generated `docs/largefile-inventory.tsv` was regenerated so its line-number
identity matches the current source.

## Release build

- Existing container: `clamav-current-rust-build-20260911`; no software was
  installed.
- Existing ARM64 static Release tree:
  `/tmp/clamav-release-current-20260913`.
- CMake cache SHA-256:
  `73ae890a7e4e8c53bb90f5448be4d9b2ba3e183703a43efc61bdf8e9a7722d92`.
- Build source manifest SHA-256 matches the source identity above.
- `ctest --output-on-failure --no-tests=error`: **28/28 passed** in
  `193.94` seconds.
- The matrix included all 21 large-file controls/verifiers, the complete
  Release `libclamav` suite, Rust, `clamscan`, `clamd`, `clamdscan`, both
  milter targets, `freshclam`, and `sigtool`.
- `clamd` passed `121/121` checks after the test-helper correction.

## ASan/UBSan build

- Existing ARM64 `RelWithDebInfo` ASan/UBSan tree:
  `/tmp/clamav-asan-current-20260912`.
- CMake cache SHA-256:
  `7f44d6d45bac74fd8fba90eba97b418931ba4a9b7fdbf88cc6ddd89cf1fb065d`.
- Build source manifest SHA-256 matches the source identity above.
- The application/control subset, excluding only the known full
  `libclamav` timeout, passed **27/27** in `500.58` seconds. This included
  all large-file controls/verifiers, Rust, milter, `clamscan`, `clamd`,
  `freshclam`, and `sigtool`.
- The full `libclamav` target reached its configured `1,200.98` second
  timeout and exited `111` with `traverse_to: Failed open payload`; no
  AddressSanitizer or UndefinedBehaviorSanitizer diagnostic was recorded.
  This is the same known full-suite timeout documented in the prior ASan
  receipt and is not promoted as a pass.

## Disposition

- Current local application build and control matrix: `development-verified`.
- No capability was promoted to qualified. Certified Linux x86-64 execution,
  exact 32-GiB materialized edges, production CVD/service behavior,
  privileged fanotify evidence, independent format-8 bytecode/JIT evidence,
  and final release readiness remain open.
- `git diff --check` and the current source guards passed.
- No usage-reset or banked-reset tool was called. No remote source transfer or
  remote mutation was performed.
