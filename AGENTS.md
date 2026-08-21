# Agent workflow

## GitHub push batching

- `github_push_min_commit_age_seconds: 1800` (30 minutes)
- For routine progress, keep commits local and do not push after each round of work.
- Push to GitHub only when the newest local commit is at least 30 minutes old. Before pushing, verify the newest commit timestamp with `git log -1 --format=%ct` and compare it with the current time; the minimum age is 1800 seconds.
- An explicit user request to push immediately overrides this batching rule.
