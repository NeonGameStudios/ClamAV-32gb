# R03 current-source ASAN/UBSAN controls revalidation — 2026-09-13

## Scope

Rebuild the current working tree with the retained ASAN/UBSAN configuration
and re-run the bounded application and large-file controls after the latest
parser/test updates. The repository remains dirty by design; this is
development evidence, not an immutable release candidate.

## Provenance

- source mount: `/src` from the canonical working tree;
- repository HEAD: `8e837b88` (`largefile-roadmap-qualification`);
- build container: `clamav-current-rust-build-20260911`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- capability manifest SHA-256:
  `566824256a07dbc551cb35b26f9511599eb31ea185e95025ddf60a2d3f9d9803`;
- capability case map SHA-256:
  `66be959d0c9c33cc3a70504e804915ff3de16bf60b462eaac2b4cf09b819f6b9`;
- inventory SHA-256:
  `eba32135ef9d407623ee56ffee6588af69f6677fd824692c62143c0aee5c61ce`;
- `clamscan` SHA-256:
  `320c6a3519d7ef8918d5bc4b263f6802f0b22372c9d245b94f822d6a9205290f`;
- `clamd` SHA-256:
  `150b62da74520106104b050dcf2381e179e2abbdb659ddf293378ca226d9df79`;
- `CMakeCache.txt` SHA-256:
  `342f477d96232ca059ff9cee3bfe052fcfa584e216ee4b229fb83fc15dd43e25`;
- CTest log SHA-256:
  `317085fad959044e335b76a5bca9394209fcfe5793dcf77307dfd47c0195375f`;
- CTest `LastTest.log` SHA-256:
  `8fe24646d630676b6fe78896ff0c9f7656f2b7a472cc97a1fff60e4b05ba7708`;
- unit-test stderr SHA-256:
  `6d9e96c1bf0260f9430278dc11cb32504673fe4c5898cb2abda3cf60cdc4285f`.

## Result

The current source rebuilt successfully. The bounded ASAN/UBSAN controls,
excluding only the documented aggregate `libclamav` target, passed:

```text
27/27 tests passed in 533.43 seconds
```

The matrix includes all large-file control/protocol/acceptance/resource
tests, Rust integration, milter quota/protocol, `clamscan`, `clamd`,
freshclam, and sigtool. The CTest log, CTest `LastTest.log`, and unit-test
stderr contain no AddressSanitizer, UndefinedBehaviorSanitizer,
LeakSanitizer, or other sanitizer diagnostics.

The aggregate `libclamav` CTest target remains unresolved on ARM64 because
its established run exceeds the configured duration budget. It is not counted
as a pass here. Certified Linux x86-64, exact/materialized 32-GiB, production
CVD/service, privileged fanotify, resource-phase, independent format-8,
Sonic1, and final release qualification remain open.

No capability was promoted. No software was installed, no usage reset was
used, and no commit, push, GitHub workflow action, or remote branch change was
performed.
