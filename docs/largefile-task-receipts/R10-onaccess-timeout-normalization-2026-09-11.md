# R10 on-access timeout normalization — 2026-09-11

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: `ingress:on-access`

Observed gap: curl-backed on-access send and receive paths passed signed
timeout values directly to the unsigned socket-wait helper. A negative API
value could therefore become a very large wait interval. In addition, a
`select()` failure in the curl-backed line reader returned with the previous
`CURLE_AGAIN` status instead of a receive error.

Implemented slice:

- `clamonacc/client/communication.c` now normalizes non-positive send and
  receive timeout values to the existing zero-wait contract before calling
  `onas_socket_wait()`.
- Curl-backed receive now records `CURLE_RECV_ERROR` when socket readiness
  fails, preserving timeout versus transport-error classification.
- Existing descriptor-backed timeout normalization remains in place, so all
  on-access communication wait paths use defined unsigned timeout inputs.
- The shared clamd command sender now preserves the native `ssize_t` result from
  `send()` while draining its bounded unsigned wire length.
- The on-access capability wording and source guards now bind these
  guarantees.

Evidence:

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — 147 passed,
  2 expected skips.
- `git diff --check` — passed.
- `sh tools/largefile_source_guards.sh` — passed with 597 capability
  bindings, including refreshed inventory/snapshot and acceptance controls.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`
  and regenerated-inventory comparison — passed.
- Current source-manifest SHA-256:
  `5183c325e03e21e3fd09e6f01723d4a1bc100104484857198fd3971daccaed94`.

No capability was promoted. Current-source linked on-access execution,
certified Linux x86-64, full-size service parity, sanitizer, privileged
fanotify, production-CVD, R04 acceptance, and final release qualification
remain open. No remote execution, remote SSH, usage reset, commit, push, or
GitHub workflow action was used.

Follow-on current-source syntax verification (2026-09-11 UTC): the
disposable `rust:1.97-bookworm` toolchain passed warning-as-error syntax
checks for the changed `clamonacc/client/communication.c`,
`clamonacc/client/protocol.c`, and `clamd/session.c` units, using the same
temporary JSON type stub where the image lacks JSON-C headers. No dependency
was installed; the current source-manifest SHA-256 is
`cd5a9c391c706e45b9b7f9bc58d908b39a85e6e32c8bd403187bcb9349467eeb`.
