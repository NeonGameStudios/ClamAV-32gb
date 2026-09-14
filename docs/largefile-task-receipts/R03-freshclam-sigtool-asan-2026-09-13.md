# `freshclam` and `sigtool` integration — ASan/UBSan (2026-09-13)

## Scope

Run the remaining lightweight application executable targets in the
current-source ARM64 `RelWithDebInfo` ASan/UBSan build.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `freshclam` SHA-256:
  `6c74270bc89234b7e025f29327d457a4073afe9cf8f4cb3b71bf7605f7c581ac`;
- `sigtool` SHA-256:
  `09584a84465bd811973fc4c69f3ee9883e5d7de54f56f6196e94f83fa2e2188d`;
- `CMakeCache.txt` SHA-256:
  `cfcb0fab0294875622cf295f6cb28f4ad95435e68015a86044e78540779dff50`;
- configuration: `RelWithDebInfo`, ASan/UBSan in C and C++, frame pointers
  retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`,
  `ENABLE_UNRAR=ON`.

## Result

```text
ctest --test-dir /tmp/clamav-asan-current-20260912 -V \
  -R '^(freshclam|sigtool)$'
```

Both targets passed (`2/2`) in 41.11 seconds. The `sigtool` harness ran 6
tests in 12.395 seconds with zero failures and zero errors. The `freshclam`
suite and `sigtool` suite handled their expected negative update, signature,
verification, diff, and build cases. The captured output contained no
`AddressSanitizer`, `LeakSanitizer`, `UndefinedBehaviorSanitizer`, or
`runtime error:` diagnostics.

This is current-source ARM64 development evidence. It does not establish
certified x86-64, exact 32-GiB/materialized-resource, production CVD/service,
privileged fanotify, Sonic1, independent format-8, or final release
qualification.
