# R10 current-source ingress syntax verification — 2026-09-11

Task ID / parent milestone: `R10` / `R00`

Scope: warning-as-error syntax validation for the changed service and client
ingress units after the milter send-deadline correction.

Canonical checkout: `/Volumes/512gbNVME/github-external/ClamAV-32gb`, branch
`largefile-roadmap-qualification`; the working tree was intentionally dirty
and preserved.

Verification used the existing disposable `rust:1.97-bookworm` Docker image,
the retained generated build include directory, and a temporary JSON type
declaration stub because the image does not provide the JSON-C development
header. No dependency was installed and no remote execution was used. Each
translation unit passed `cc -DHAVE_CONFIG_H ... -Wall -Wextra
-Wformat-security -Werror -std=gnu90 -fsyntax-only`:

- `common/clamdcom.c`
- `common/actions.c`
- `clamd/session.c`
- `clamd/scanner.c`
- `clamdscan/client.c`
- `clamdscan/proto.c`
- `clamonacc/client/communication.c`
- `clamonacc/client/protocol.c`
- `clamav-milter/clamfi_quota.c`
- `clamav-milter/netcode.c`

The current source-manifest SHA-256 is
`cd5a9c391c706e45b9b7f9bc58d908b39a85e6e32c8bd403187bcb9349467eeb`.
This is compile-boundary evidence only; it does not claim a linked current
binary, certified Linux x86-64 execution, full-size service parity, sanitizer,
milter runtime, R04 acceptance, or release qualification.
