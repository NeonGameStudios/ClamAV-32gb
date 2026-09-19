# R08 — Mail HTML normalization uses the message-owned temporary directory

Date: 2026-09-19
Task ID / parent milestone: `R08` / Documents and normalization

Exact capability kind:id list: mail/MIME and HTML normalization cases exercised
by the focused `cl_scan_api` regressions; no capability row was promoted to
qualified.

## Starting identity and prerequisites

- Branch: `largefile-roadmap-qualification`
- Starting commit: `59155530` (`Close OneNote spool writers after materialization`)
- Remote validation host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container image: `clamav-32gb:dev-current`, image ID
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Build directory: `/tmp/clamav-7f3458c4-build`
- The focused source files were checked against the local candidate. Local and
  remote `libclamav/mbox.c` SHA-256: `cfedd2d38d4f5168fca9ff32269e27ba1d0626e7a0d71918f37e1cbf01f8f61b`.
  Local and remote `libclamav/htmlnorm.c` SHA-256:
  `e911c4d67816c6ce669fd8fd4f1e214798c404d04a4b6a3281dba5222bd3f1c2`.

## Observed gap and change

Archive-with-mail and large mail/MHTML cases previously returned `CL_EFORMAT`
with “HTML phishing input could not be normalized completely”. The mail
scanner's `getHrefs()` used the shared scan temporary directory, while HTML
normalization writes fixed filenames (`nocomment.html` and `notags.html`).
That allowed concurrent or nested mail scans to collide.

`libclamav/mbox.c` now prefers `mctx->dir`, the temporary directory owned by
the parsed message, and falls back to `ctx->this_layer_tmpdir` only when the
message directory is unavailable. No parser assertion or expected result was
weakened.

## Development verification

The current source rebuilt the focused target successfully:

```text
cmake --build /tmp/clamav-7f3458c4-build --target check_clamav -j2
[100%] Built target check_clamav
```

The complete asynchronous `cl_scan_api` run finished against the rebuilt
binary with exit 0 and no stderr:

```text
Running suite(s): cl_suite
100%: Checks: 839, Failures: 0, Errors: 0
```

The mail/HTML cases were also inspected in smaller runs while diagnosing the
original failure. Those focused runs passed:

| Focus | Checks | Failures | Errors |
| --- | ---: | ---: | ---: |
| archive/mail pair | 2 | 0 | 0 |
| MHTML pair | 2 | 0 | 0 |
| streaming-spool single-message case | 3 | 0 | 0 |
| single-message no-alert case | 4 | 0 | 0 |

The temporary remote test-selection harness was removed after the focused
runs. The remote test source retains one unrelated pre-existing extra PDF test
registration, so it is not used as a whole-file identity claim; the complete
run above is nevertheless the rebuilt binary's full linked `cl_scan_api`
result.

## Boundary and next action

The earlier full run had 17 failures before this fix; the complete current
run now passes all 839 checks. This is development evidence only: it does not
provide certified x86-64, sanitizer, production-service, R04 acceptance, or
release qualification evidence. The broader R08 parser matrix and remaining
roadmap gates remain open.

State: `development-verified`; qualification pending.
