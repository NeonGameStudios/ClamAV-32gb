# Agent workflow

## Usage reset prohibition

- Never trigger, redeem, or consume a banked usage-reset or rate-limit-reset credit, even if the user asks. Continue only with the currently available execution budget or report the limitation.

## GitHub push batching

- `github_push_min_commit_age_seconds: 1800` (30 minutes)
- For routine progress, keep commits local and do not push after each round of work.
- Push to GitHub only when the newest local commit is at least 30 minutes old. Before pushing, verify the newest commit timestamp with `git log -1 --format=%ct` and compare it with the current time; the minimum age is 1800 seconds.
- An explicit user request to push immediately overrides this batching rule.

## GitHub CMake workflow consent

- Do not update, enable, dispatch, rerun, or otherwise trigger GitHub's
  `CMake Build` workflow without explicit user consent.
- This restriction applies to `main` and every current or future branch,
  including changes to `.github/workflows/cmake.yml`, workflow-dispatch
  requests, reruns, and pushes that would trigger the workflow.
- Preserve the repository-level disabled state for the CMake workflow unless
  the user explicitly authorizes changing it.
