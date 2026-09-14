# R09 required application rows — ASan/UBSan follow-up (2026-09-13)

## Scope

Run the current-source ARM64 `RelWithDebInfo` ASan/UBSan `clamscan` against
the focused R09 application rows that were already green in the Release
integration harness:

- fuzzy-image matching and disable controls;
- recognized Python and ONNX parser failures with raw-detection precedence;
- classifier-only ignored-type behavior and fail-visible status;
- production UnRAR extraction for RAR and neutral-prefix RAR-SFX inputs.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `clamscan` SHA-256:
  `1b9a4bfc0fd9eb99b1cbd84cadbf787e70bd89516f484bffa477efb0e40e7df2`;
- `CMakeCache.txt` SHA-256:
  `cfcb0fab0294875622cf295f6cb28f4ad95435e68015a86044e78540779dff50`;
- configuration: `RelWithDebInfo`, ASan/UBSan in C and C++, frame pointers
  retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`,
  `ENABLE_UNRAR=ON`;
- incremental rebuild: exit 0, all targets reached 100%.

## Result

From `/src/unit_tests`, the following command completed with exit 0:

```text
python3 -m unittest \
  clamscan.fuzzy_img_hash_test \
  clamscan.r09_parser_policy_test \
  clamscan.ignored_type_test \
  clamscan.rar_backend_test --verbose
```

`Ran 7 tests in 13.172s` and `OK`.

The run verified exact and bounded fuzzy-image matches, malformed-signature
rejection, image-scan disable controls, Python and ONNX raw-match precedence,
ignored-type raw-match precedence and unsupported-input failure visibility,
and nested detections from both the valid RAR4 and neutral-prefix RAR-SFX
fixtures. The UnRAR cases emitted no archive-incomplete warning.

The captured output contained no `AddressSanitizer`, `LeakSanitizer`,
`UndefinedBehaviorSanitizer`, or `runtime error:` diagnostics.

This is current-source ARM64 development evidence. It does not establish
certified x86-64, exact 32-GiB/materialized-resource, production CVD/service,
privileged fanotify, Sonic1, independent format-8, or final release
qualification.
