# R12 exact-materialized ClamScan edge follow-up

Date: 2026-09-26

## Candidate and input identities

- Repository/branch: `ClamAV-32gb`, `largefile-roadmap-qualification`.
- Candidate HEAD: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; source working
  tree is dirty.
- Sonic1 container: `37c15f1f08b9325834e0dc487c09e6e0631c62275a9deb3e93654266cc042bb5`.
- Container image:
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Runtime build source manifest:
  `cbe3bf9835244a7772fedac0be958c670792aaca5d98248f86addff4113f864d`.
- Runtime build identity SHA-256:
  `a4d267c325113973c6435f6cedde7e3a80c93f3dfa539752d1c8747b7debd938`.
- ClamScan SHA-256:
  `998b1c734b5dfe24ce65593d363dc0f55e6010a35d3f85e2f96e8012703c310b`.
- Exact edge fixture: `/ram/edge-stable.bin`, 34,359,738,368 bytes,
  34,359,746,560 allocated bytes, no hole through EOF.
- Fixture SHA-256 before and after the scan:
  `98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.

## Exact ClamScan execution

Managed Sonic1 job `job_c692ea16032d417789e4d22f1979b4c7` ran the candidate's
ClamScan against `/ram/edge-db-v32` and the fully allocated edge fixture.
Elapsed wall time was 159.518 seconds. The engine report recorded status 1,
`DETECTION_TERMINATED`, strong detection `NDB.LargeFile-Edge.UNOFFICIAL`,
root/logical size 34,359,738,368, matcher bytes 34,368,129,024, zero skipped
operations, and alert offset 34,359,738,352 (exactly EOF−16). The text log
reported the same signature.

The scanner completed without changing the fixture. Peak sampled RSS was
102,629,376 bytes and PSS 100,237,312 bytes; minimum host `MemAvailable` was
65,165,500,416 bytes. Swap remained zero, host `oom_kill` remained 44, and the
run's temporary directory was empty afterward. No new daemon was started; this
direct-path test does not waive the separate 68-GiB disk admission rule for
daemon/on-access qualification.

The original verifier rejected the run only because `/ram/oracle.tsv` expects
`CL_TYPE_DATA`, which is not a candidate file-type enum. The report correctly
returned the defined generic binary type `CL_TYPE_BINARY_DATA`. The original
oracle was left unchanged (SHA-256
`ea1b38f07ce78ca278608094e470e7e21b07431a3d950d18c3d33a765f56cb96`). A
separate reconciliation copy changed only `edge.expected_type` to
`CL_TYPE_BINARY_DATA`; the candidate's workload verifier then accepted the
size, completion, status, signature, exact offset, verdict, log and type.
Reconciliation artifacts are alongside the run at
`/qualification/r13-report-consistency-fix-v3-20260925/runs/r32g-clamscan-edge-20260926-v1/`.
The original fixture oracle and original failed-verification result remain
preserved; this corrected copy is not yet the fixture package's canonical
oracle.

## Library test harness correction and remaining verification

An initial attempt to run the prebuilt `check_clamav` test used
`/ram/materialized-disk.bin`, a different fully allocated fixture with no
edge marker, and therefore failed before scanning. That result is not a
scanner failure. It exited after 27.154 seconds with the prebuilt test binary
SHA-256 `5a751828edb4ba4d7eaa579c0d6d02d5597ab7bf11cccd5f76cfd2d3d57864ed`;
the retained result is at
`/qualification/r13-report-consistency-fix-v3-20260925/runs/r32g-library-exact-materialized-20260926-v1/`.
The current local test source now uses the marker actually
present in `edge-stable.bin` (`EDGE-LATE-MARKER` at EOF−16), checks the exact
report alert offset, and expects the candidate's defined `CL_TYPE_BINARY_DATA`
type. The updated source SHA-256 is
`f4c76ceb00a5701e86ab4c21bfcd18101d8b1fc094ae2847afb093cdc3299aca`; the
updated local source manifest SHA-256 is
`06ca8645e3f250be4a1bad8bf2b7ce1e879e5431b52459af18ac380b4f8da30b`.

That modified C test has not yet been compiled or executed on Sonic1. The
prebuilt test binary predates the local harness correction. The source change
is development work only; it does not qualify the library path, descriptor,
or fmap capabilities, and the release gate remains blocked.

## Follow-up verifier correction

The failed wrapper was caused by an oracle-schema gap: it accepted any
syntactically shaped `CL_TYPE_*` value, even when the candidate could not emit
that value. `tools/largefile_service_workload_check.py` now derives the allowed
report types from this candidate's `libclamav/filetypes.c` map and rejects
unknown values during `--check-inputs`, before a scan can start. Its regression
test proves `CL_TYPE_DATA` is rejected and `CL_TYPE_BINARY_DATA` is accepted.
The synthetic service-evidence control now copies `filetypes.c` into its
isolated miniature source tree so it exercises the same check.

Verification on the local source tree: 87 focused Python tests passed (2
Linux-filesystem-only tests skipped on macOS), the service-evidence regression
passed, the public `--check-inputs` path was verified to reject the invalid
type before touching any fixture, the source guards passed across all 604
capability entries, and `git diff --check` passed. These are harness/source
checks only. The successful
remote ClamScan receipt above used an independently corrected oracle copy; a
fresh Sonic1 job is still required to bind this fix to a rebuilt,
provenance-identified candidate. The existing remote RAM-fixture writer remains
listed as running; a status request timed out during SSH connect, so it was
neither assumed complete nor restarted or canceled.
