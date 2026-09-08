# Small qualification improvements — 2026-09-05

These changes strengthen the roadmap's acceptance tools. They do not promote
any capability to release-qualified.

## Consistent outcomes

The service oracle, direct framed report probe, and post-run verifier now
enforce the same outcome relationships:

| Completion | Expected CLI exit | Signature |
| --- | ---: | --- |
| `COMPLETE` | 0 | None |
| `DETECTION_TERMINATED` | 1 | Required |
| Limit, unsupported, malformed, resource, or abort incomplete | 2 | None |

An expected-results file cannot make a contradiction valid by repeating it.
The observed report must still match the oracle's status, verdict, alert,
offset, type and counters. A detection can retain earlier skipped operations,
as allowed by the engine's detection-precedence rule; a complete clean result
cannot. These are workload expectations, not a change to engine verdicts.

## Exact signature fields

The producer and post-run verifier share a parser for the signature field in
`input: Signature.Name FOUND` lines. It permits the standard `.UNOFFICIAL`
suffix and the daemon's optional hash/size decoration. Prefix/suffix matches,
names appearing only in a filename or a debug line, and unrelated `FOUND`
lines do not satisfy the expected detection. Debug offsets must belong to
the exact signature and the complete expected number.

The synthetic fixtures now use this real log shape. A frontend that emits
only `input: FOUND` cannot by itself supply exact-signature log evidence;
structured reports still undergo their own exact alert checks. These gate
changes do not add signature names to frontend console output.

## Separate oversized descriptor rejection

`tools/largefile_service_oversize.py` creates a private, sparse regular file
of exactly **34,359,738,369 bytes**, passes its descriptor through
`FILDESREPORT`, and requires a specific `MaxFileSize` rejection:

- The report must identify the exact input size and a 32-GiB MaxFileSize.
- With alerts off: `CL_EMAXSIZE`, no detection verdict, `LIMIT_INCOMPLETE`,
  and the exact `Heuristics.Limits.Exceeded.MaxFileSize` reason.
- With alerts on: the exact size-policy alert and reason, a detecting verdict,
  and `DETECTION_TERMINATED`; unrelated malware, other limits, generic `FOUND`,
  and resource errors cannot count as the expected rejection.
- No reported parser or matcher work, logical-byte accounting, or temporary staging; unchanged fixture metadata;
  confirmed fixture removal; daemon PONG responses before and after.

The service producer runs the probe against its private daemon and records
`oversize-fildesreport` in the workload manifest, with JSON evidence under
`reports/oversize-fildesreport.json`. The independent verifier requires and
rechecks that record. Recomputed checksums do not make a different rejection
reason or a missing workload acceptable. The nine-argument producer interface
and existing four-role oracle remain unchanged. The current evidence schema
also supports a fail-closed bundle containing mode-bound alerts-off and
alerts-on reports; the qualification sequence restarts clamd between modes
and restores the alerts-on profile before continuing.

The sparse fixture is deliberate: this negative test exercises size admission
without allocating or reading 32 GiB. It is **not** the fully allocated
oversized release fixture, acceptance of a valid 32-GiB file, or coverage of
every CLI/stream/on-access mode. Full certification still requires those runs.
There is no production size override. Lightweight tests confine fake responses
or reduced limits to their own process.

The sparse boundary corpus now has a separate admission oracle:
`largefile_boundary_corpus_check.py` validates all eleven reviewed rows,
logical sizes, marker bytes, sparse allocation, and fixture stability before a
runtime scan and again during evidence verification. This catches a truncated
or substituted corpus, but it does not turn sparse metadata/marker checks into
the required live current-source scan.

## Short generated status

Start with [32gb-current-snapshot.md](../32gb-current-snapshot.md). Its generated
counts come from the existing readiness gate and shared exclusion policy; it
distinguishes all parser rows from enabled parser rows. HEAD and manifest/gate/
allowlist hashes bind the snapshot inputs. Maintained roadmap reminders are
explicitly separated from computed results.

```sh
python3 tools/largefile_status_snapshot.py --output 32gb-current-snapshot.md
python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md
```

The source guards check snapshot freshness. The generator does not certify
the whole source tree or convert status labels into independent proof.

## Regression controls

```sh
sh tools/largefile_service_evidence_check_test.sh
python3 -B tools/largefile_status_snapshot_test.py
sh tools/largefile_source_guards.sh
```

The service controls include 21 input-policy tests, 10 result/log tests, and
22 oversized-probe tests; the snapshot adds nine tests.
Tests cover real sparse descriptor creation and fragmented report framing,
but their simulated daemon responses are not production service evidence.

A coherent current-source ARM64 Debug build has since completed in the
disposable toolchain container, and the freshly linked `clamscan` reports
`ClamAV 1.5.3-largefile-devel`, accepts `--help`, and detects the repository
logo through a temporary fuzzy-image signature with the expected detection
exit. The same current-source `clamd` starts, answers `PONG`, and its
`clamdscan` client detects the logo over both file and stdin/stream paths while
returning clean for a control file. Current-source structured path reports now
also pass for both detection and clean outcomes after fixing the path request's
`sendln()` success handling; stream structured reports remain passing. A
production-linked Rust fuzzy-image test group also passes 9/9. These are development smoke results, not the retained
R04 daemon/service records; the oversized rejection still requires a suitable
runner, and an old binary was not used as evidence.
A source-derived test verifies `CL_EMAXSIZE = 24` against `libclamav/clamav.h`.

Validation completed: all 62 focused tests passed on the existing Linux
container (21 input-policy, 10 result/log, 22 oversized-probe, nine snapshot),
along with the shell service-evidence regression. macOS passed the same
controls with the two Linux-only filesystem tests skipped. Canonical-source
guards, capability-manifest validation, readiness regression tests, snapshot
freshness and diff whitespace checks passed. Capability statuses remain unchanged.
