# R03 local Linux artifact identity check — 2026-09-20

## Scope

Check whether the existing local Linux ARM64 build can serve as current-source
application evidence. A mismatched or differently configured artifact must not
be reused as proof for the current candidate.

## Evidence

Artifact root: `/private/tmp/clamav-native-linux-current`.

- `clamscan` and `libclamav.so` are Linux ARM64 ELF artifacts.
- Build cache source root: `/src`.
- Build type: `RelWithDebInfo`.
- `ENABLE_TESTS=ON`, `ENABLE_MILTER=ON`, `ENABLE_CLAMONACC=ON`.
- `ENABLE_LARGE_FILE_DEFAULTS=OFF`.
- retained artifact source manifest: 1,706 rows,
  SHA-256 `e0e421f2dbf8f118c91753645b8b1384220f7ba8890a03e55ff3245365f07178`.
- current clean candidate manifest: 1,710 rows,
  SHA-256 `f7def859347ea1473e8d52014fb78a61765b5e8a77ee54673dc2427a436a5`.
- sorted manifest comparison differs in 82 lines.

The artifact therefore does not identify the current candidate and also was
not built with the large-file defaults. It is not used for current-source or
qualification evidence.

## State

State: `artifact-rejected-stale-or-misconfigured`.

No artifact was modified, no source status was changed, and no capability was
promoted. A new build from the current candidate still requires a complete
toolchain and permitted source staging path.
