# Task receipt: R09 ignored-type CLI behavior

Task ID / parent milestone: `R09` / `R00`

Exact capability: `parser:CL_TYPE_IGNORED`

Scope: verify the classifier-only ignored-type contract through the real
production-linked `clamscan` ingress. Recognized ignored input has no deep
parser, must remain incomplete/non-cacheable when no detection occurs, and
must still allow the outer raw matcher to report malware.

## Implementation and regression

- Added `unit_tests/clamscan/ignored_type_test.py`.
- The test creates a minimal ID3/MP3 input, which the current classifier
  recognizes as an ignored type, and an exact NDB raw signature.
- The matching input returns `Ignored.Raw.UNOFFICIAL FOUND` with exit 1 and
  retains the `recognized ignored file type parser is unsupported` warning.
- A same-shape nonmatching input returns `Can't parse data ERROR` with exit 2,
  zero scanned/infected files, and the same explicit warning.
- The source guard pins the diagnostic in this CLI regression so the test
  cannot be removed while retaining only direct-library coverage.

## Evidence

- Container: `clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.
- Build directory: `/tmp/clamav-release-current-20260912`.
- Scanner SHA-256:
  `b085b063e507da218d1ea5ed3436a91a7572bcf11462c4ec9ff3daa17eaa99c6`.
- Current source manifest SHA-256:
  `7d24df9d37ea3167e3c17509b7cfa73e7bd0b3120ace5234e76fbdf1735059d0`.
- Detected input (`ID3CLAMAV-IGNORED-RAW`) SHA-256:
  `4337bd483962cb3dce3f3b0ac85ff60ece0493526334249c9e742cc8cc5a607c`.
- Nonmatching input (`ID3CLAMAV-IGNORED-CLEAN`) SHA-256:
  `c9a3f21604ba7f380babd387224653b309eae45f0fc173baf10f1aabb8890f6f`.
- NDB SHA-256:
  `5648959696dec687e70aa7b1f16d42ccb5e9adfc9121be70edf28555239f657f`.
- Current-source `clamscan` CTest target passed after adding the regression.

This closes the real CLI development behavior gap for the ignored classifier,
but the required R09 row remains `pending`: full-size, sanitizer, certified
Linux x86-64, production-CVD/service, Sonic1, and final release evidence are
still required.
