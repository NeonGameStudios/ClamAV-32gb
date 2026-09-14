# Task receipt: R03 large-file qualification platform gate

Task ID / parent milestone: `R03`

The current ARM64 Docker development environment was checked for the
roadmap-specific `largefile_qualification` TCase. The existing ASan build has
`ENABLE_LARGE_FILE_QUALIFICATION_TEST=OFF`, so selecting
`CK_RUN_CASE=largefile_qualification` produced zero checks and was not counted.

A separate out-of-tree ASan/UBSan configuration was then attempted with
`ENABLE_LARGE_FILE_QUALIFICATION_TEST=ON`. CMake failed closed before
generation with the source guard:

```text
ENABLE_LARGE_FILE_QUALIFICATION_TEST is restricted to the qualified Linux x86-64 profile
```

This confirms that the exact-32-GiB qualification test cannot be enabled on
the current ARM64 development container and that the repository does not
permit bypassing the platform contract. No source/build tree was altered
beyond the disposable incomplete configuration directory.

In the same fresh sanitizer window, the enabled Mach-O unsupported-policy
slice passed 2/2 checks with zero failures/errors and no sanitizer diagnostics.

The missing qualified Linux x86-64 runner remains the exact external
dependency for the largefile qualification TCase. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
