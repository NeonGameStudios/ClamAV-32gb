# Task receipt: current-source production-linked ARM64 parser checks

Task ID / parent milestone: `R09` / `R00`

Scope: rerun the required parser/matcher slices against the current source
through the CMake-built production ABI in the disposable ARM64 Docker
toolchain. This is development evidence only; it does not promote any
capability to release-qualified status.

Validation:

- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=required_unsupported` passed `38/38`
  checks with zero failures and errors.
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rar` passed `11/11` checks with zero
  failures and errors, covering backend error mapping, archive lifecycle,
  nested staging, timeout, and unavailable-backend behavior.
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=gif` passed `16/16` checks with zero
  failures and errors, including the bounded fuzzy-image reader and working-
  set admission regressions.
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote`, `onenote`, and `rust_map`
  each passed `2/2` checks with zero failures and errors.
- The executable was rebuilt from the current checkout in the persistent
  temporary CMake build directory; the test binary was run after copying the
  build into the container's native filesystem so Unix-runtime dependencies
  and test sockets were not affected by host-mounted filesystem semantics.

Boundaries:

- The runtime packages needed by the test binary (`libsubunit0` and
  `libjson-c5`) were installed only inside a disposable container. No host
  software was installed.
- These ARM64 results validate current-source production-linked behavior but
  are not certified Linux x86-64 evidence, independent format-8 Python
  evidence, production-CVD/service evidence, materialized 32-GiB evidence,
  sanitizer evidence, or final release qualification.
- The seven required R09 rows remain `pending`; no capability status was
  promoted. No remote execution, usage reset, banked reset, commit, push, or
  GitHub workflow action was performed.

State: `development-verified`; certified qualification remains blocked on the
external x86-64 runner and the remaining roadmap evidence.
