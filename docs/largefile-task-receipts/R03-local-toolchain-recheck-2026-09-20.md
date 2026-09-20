# R03 local Docker toolchain recheck — 2026-09-20

## Scope

Try the clean current candidate in each pre-existing local Docker toolchain
image, without installing software or disabling required ClamAV dependencies.
This is build-readiness evidence only; no capability was promoted.

## Commands and results

The current source was mounted read-only and configured with:

```text
docker run --rm \
  -v /Volumes/512gbNVME/github-external/ClamAV-32gb:/src:ro \
  -w /src clamav-largefile-local-toolchain:latest \
  cmake -S /src -B /tmp/clamav-cmake-current-local \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=OFF -DENABLE_APP=OFF \
  -DRUSTUP_TOOLCHAIN=stable
```

The command reached Rust discovery successfully (`cargo`, `rustc`, and
`rustup` 1.98.1) and then exited **1** because BZip2 development headers and
libraries were missing:

```text
Could NOT find BZip2 (missing: BZIP2_LIBRARIES BZIP2_INCLUDE_DIR)
```

The other pre-existing image, `clamav-largefile-local-toolchain2:latest`,
reached Rust discovery at 1.97.1 and then stopped at its known missing JSON-C
development files. Neither image provides a complete current-source local
build environment.

## State and next action

State: `local-toolchain-blocked-external`.

No dependency was installed, no required feature was disabled, and no
qualification claim was made. Continue with existing local source/Rust and
acceptance verification; a complete current-source native build requires an
authorized runner or a pre-existing image containing the required native
development dependencies and a permitted source staging path.
