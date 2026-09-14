# R03 current-source Release controls revalidation — 2026-09-13

## Scope

Rebuild the current working tree and re-run the configured application and
large-file Release controls after the latest parser/test updates. The
repository remains dirty by design; this is development evidence, not an
immutable release candidate.

## Provenance

- source mount: `/src` from the canonical working tree;
- repository HEAD: `8e837b88` (`largefile-roadmap-qualification`);
- build container: `clamav-current-rust-build-20260911`;
- build directory: `/tmp/clamav-release-current-20260913`;
- capability manifest SHA-256:
  `566824256a07dbc551cb35b26f9511599eb31ea185e95025ddf60a2d3f9d9803`;
- capability case map SHA-256:
  `66be959d0c9c33cc3a70504e804915ff3de16bf60b462eaac2b4cf09b819f6b9`;
- inventory SHA-256:
  `eba32135ef9d407623ee56ffee6588af69f6677fd824692c62143c0aee5c61ce`;
- `clamscan` SHA-256:
  `5d06220f744307834bf6ee1181aae334ace8266a1a56395a85b8aa2f1756774a`;
- `clamd` SHA-256:
  `f8afa1d0d79cc21a440395985ce771a8dc8415695c536794c7e1565dcc2bd17d`;
- `CMakeCache.txt` SHA-256:
  `af2fe69b889f05d0ab5b6b87d1bb742873825371d8226e6a414275a74c08d959`;
- CTest log SHA-256:
  `3eaa8319d03b1fec7274bce04aea5087a50b33072ad632a555f489913da29dde`.

## Result

The current source rebuilt successfully. The configured Release controls,
excluding only the documented aggregate `libclamav` target, passed:

```text
27/27 tests passed in 149.63 seconds
```

This includes the large-file control/protocol/acceptance/resource tests,
Rust integration, milter quota/protocol, `clamscan`, `clamd`, freshclam, and
sigtool. A separate bounded ARJ revalidation passed `arj` 14/14,
`arj_map` 8/8, `arj_compressed` 2/2, and `arjsfx` 5/5.

The aggregate `libclamav` CTest target remains unresolved on ARM64 because
its established run exceeds the configured duration budget. It is not counted
as a pass here. Certified Linux x86-64, exact/materialized 32-GiB, production
CVD/service, privileged fanotify, resource-phase, independent format-8,
Sonic1, and final release qualification remain open.

No capability was promoted. No software was installed, no usage reset was
used, and no commit, push, GitHub workflow action, or remote branch change was
performed.
