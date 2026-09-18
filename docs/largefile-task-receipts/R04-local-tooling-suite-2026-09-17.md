# R04 local tooling-suite revalidation — 2026-09-17

## Scope

Run every dependency-light Python test under `tools/` against the current
working tree. This validates the acceptance schemas, evidence binders,
resource-policy helpers, service/report protocols, boundary-corpus checks,
snapshot generation, and other roadmap support tooling. It is development
evidence only and does not qualify the ClamAV C/Rust application or release.

## Command and result

```text
python3 -B -m unittest discover -s tools -p '*_test.py'
```

The command exited 0:

```text
Ran 199 tests in 16.182s
OK (skipped=2)
large-file acceptance record schema passed (14 records)
```

The two skips are declared by the test harness; no test failed. The run used
the existing local Python interpreter and repository files only. No network
access, package installation, usage reset, or remote mutation was used.

Additional dependency-light controls also passed:

```text
python3 -B tools/largefile_service_result_check_test.py       # 10 passed
sh tools/largefile_poc_fail_closed_test.sh                    # passed
sh tools/largefile_runtime_evidence_check_test.sh             # passed
sh tools/largefile_service_evidence_check_test.sh             # passed
```

The procfs RSS control reported its documented Linux-unavailable skip. The
on-access configuration control was not run because no current-source
`clamonacc` executable exists in the available local build artifacts; it
requires that executable as its explicit argument.

## Boundary

The full C/Rust build, linked application tests, certified Linux x86-64
qualification, production databases, materialized large-file cases, and
Sonic1 execution remain open under the roadmap.

State: `development-tooling-verified; application-qualification-open`
