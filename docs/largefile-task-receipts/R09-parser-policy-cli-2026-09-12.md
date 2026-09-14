# Task receipt: R09 recognized parser policy through clamscan

Task ID / parent milestone: `R09` / `R00`

Exact capabilities: `parser:CL_TYPE_PYTHON_COMPILED` and
`parser:CL_TYPE_AI_MODEL`

Scope: verify the current bounded parser policies through the real
production-linked `clamscan` ingress. Recognized malformed inputs must remain
explicitly incomplete, while outer raw matching must still report malware.

## Inputs and expected behavior

- Python input: an eight-byte recognized Python bytecode header, plus a
  fourteen-byte variant with the exact `PY-RAW` marker at offset 8.
- AI-model input: a thirteen-byte recognized ONNX ModelProto prefix missing
  required fields, plus a nineteen-byte variant with `AI-RAW` at offset 13.
- The matching NDB contains `Python.Raw` and `AI.Raw` signatures at those
  offsets.
- Both clean parser cases returned their parser-specific incomplete
  diagnostic with exit 2, zero scanned/infected files, and no clean verdict.
- Both marker cases returned the expected `*.UNOFFICIAL FOUND` result with
  exit 1 and one scanned/infected file.

## Evidence

- Container: `clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.
- Build directory: `/tmp/clamav-release-current-20260912`.
- Scanner SHA-256:
  `b085b063e507da218d1ea5ed3436a91a7572bcf11462c4ec9ff3daa17eaa99c6`.
- Current source manifest SHA-256:
  `13247cfac5c772a5d7e429a05cec1c5bdc041f82e5175a2caa6353f0e357916a`.
- Python clean/detected input SHA-256:
  `8a96df12ec0ffd31dd9b0800d5801e15ceb7eb7f077ded0761e2dfa9204c7e20` /
  `be790e2142fa6964116ac07dc10d88666e73fa62343ac25e743e3fc6fe226c01`.
- AI clean/detected input SHA-256:
  `393f07174f72aab3b7573b92e959a0d5fd5df5ffa5072111c0bb44478dabc556` /
  `3ec9f5ae0d4552892976ea773863df3ae16eda4948be1d07ba60228da43198c6`.
- NDB SHA-256:
  `cce18c74cbc6540f353a1ca611df3788252f7e2cce38e7b180cedbaf309a5aef5`.
- The current-source `clamscan` aggregate passed after adding this case.

This strengthens development ingress evidence but does not promote either
required R09 row: full parser semantics, full-size, sanitizer, certified
Linux x86-64, production-CVD/service, Sonic1, and final release evidence
remain required.
