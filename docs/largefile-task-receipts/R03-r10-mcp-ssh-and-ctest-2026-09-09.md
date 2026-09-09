# Task receipt: remote qualification retry and CTest allowance

Task ID / parent milestone: `R03` / `R10` follow-up across the five-issue
roadmap review

Date: 2026-09-09

Canonical source and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- intentionally dirty working tree preserved

## Remote qualification retry

MCP-SSH host discovery returned the exact host IDs `sonic3` and `sonic1`.
The supplied `sonic3-sudo` profile was described successfully for `sonic3`.
Three side-effect-free commands (`pwd`, `ls -la`, and `docker ps -a`) then
timed out during SSH connect after 20 seconds each; no remote command started.
The prescribed connection diagnostic was policy-denied with
`no_matching_allow_rule`. Retrying the previously requested `sonic1` host
with the supplied profile was also policy-denied with
`login_profile_not_allowed_for_host`. No remote source transfer, Docker
execution, or test run was performed.

This leaves the certified remote runner prerequisite unavailable for this
turn. The profile was not guessed or substituted.

## Local CTest correction

The configured CTest timeout for `largefile_development_acceptance_capture`
was raised from 60 seconds to the existing 300-second allowance used by the
inventory/source and runtime evidence controls. The standalone capture test
had passed but was close enough to the 60-second limit to time out in the
broader configured container run. This is a harness allowance only; no
assertion, expected result, readiness rule, or capability status changed.

## Verification

- `sh tools/largefile_source_guards.sh`: passed; 597 capability rows and all
  local acceptance/source controls passed.
- `git diff --check`: passed.
- No host software was installed.
- No usage reset or banked reset was used.
- No commit, push, or GitHub CMake workflow action was performed.

State: `development-verified`; certified runner, full-size evidence, and
release qualification remain blocked by external prerequisites.
