# R13 clamonacc unknown-size stream deadline — 2026-09-17

## Scope

Close the on-access unknown-size stream hang at the bounded ingress boundary.
This development slice keeps the existing exact-ceiling and EOF semantics while
ensuring an open pipe/FIFO cannot hold a scan indefinitely.

## Implementation

- `clamonacc/client/protocol.c` now derives one absolute source-read deadline
  from `OnAccessCurlTimeout` after the `zINSTREAMREPORT` command is admitted.
- Unknown-size descriptors wait for readable-or-EOF with `select()` before
  each source read and before the final one-byte overflow probe.
- Repeated data does not extend the deadline; idle input returns
  `CL_ETIMEOUT`, readiness failures return `CL_EREAD`, EOF remains normal, and
  an available byte beyond the inclusive ceiling returns `CL_EMAXSIZE`.
- A zero timeout retains the existing immediate-poll behavior instead of
  turning into an unbounded source wait.
- The deadline uses a monotonic clock when available and retains a validated
  wall-clock fallback for supported POSIX builds.

## Development evidence

- `sh tools/largefile_clamonacc_stream_deadline_regression.sh` passed. The
  regression compiles the exact production deadline helpers and checks zero
  timeout polling, idle timeout, EOF readiness, available data admission, and
  a steady producer that cannot extend the same absolute deadline through real
  pipes.
- The same regression is now registered as the Unix CTest
  `largefile_clamonacc_stream_deadline` control, so configured builds exercise
  it directly.
- `sh tools/largefile_source_guards.sh` passed with 604 capability rows,
  including the refreshed deterministic inventory.

## Limits

This is bounded implementation evidence, not a linked clamonacc runtime or
full-size qualification result. Full current-source CMake rebuild, Release and
sanitizer execution, certified Linux x86-64 evidence, production databases,
fanotify permission cases, and Sonic1 revalidation remain pending because the
local build prerequisites and current-source remote connection are unavailable.
