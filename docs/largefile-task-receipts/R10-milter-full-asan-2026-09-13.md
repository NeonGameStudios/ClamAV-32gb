# Milter application targets — ASan/UBSan (2026-09-13)

## Scope

Run the registered milter quota and protocol application targets against the
current-source ARM64 `RelWithDebInfo` ASan/UBSan build.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `clamav-milter` SHA-256:
  `030fa4edc0f882a097d0520489f63f193016eae6422441e7d1b628cee1ad5979`;
- `check_clamfi_quota` SHA-256:
  `7ee271df9d6e7280ab33aeb507c346b51bba8045b3b8199fee9155aae82ee7eb`;
- `CMakeCache.txt` SHA-256:
  `cfcb0fab0294875622cf295f6cb28f4ad95435e68015a86044e78540779dff50`;
- configuration: `RelWithDebInfo`, ASan/UBSan in C and C++, frame pointers
  retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`,
  `ENABLE_UNRAR=ON`.

## Result

```text
ctest --test-dir /tmp/clamav-asan-current-20260912 -V \
  -R '^(clamav_milter_quota|clamav_milter_protocol)$'
```

Both targets passed (`2/2`) in 8.46 seconds. The quota check passed in 0.96
seconds. The protocol harness passed in 7.50 seconds and reported the
expected clean accept (`a`), infected reject (`r`), exact-limit accept (`a`),
and limit-plus-one fail-visible (`t`) outcomes. The captured output contained
no `AddressSanitizer`, `LeakSanitizer`, `UndefinedBehaviorSanitizer`, or
`runtime error:` diagnostics.

The protocol target intentionally uses the repository's 100 MiB development
limit profile; literal 32-GiB/certified milter qualification remains open.
This is current-source ARM64 development evidence and does not establish
certified x86-64, exact 32-GiB/materialized-resource, production CVD/service,
privileged fanotify, Sonic1, independent format-8, or final release
qualification.
