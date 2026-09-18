# R05 Sonic1 current-source oversized admission — 2026-09-16

## Scope

Run the roadmap's current-source sparse 32-GiB+1 `FILDESREPORT` admission
control against the current Linux x86-64 build on Sonic1. This is the
deliberate metadata boundary negative control; it is not materialized scan
qualification.

## Provenance

- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`
- Image: `clamav-32gb:dev-current`, image ID
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Source mount: `/tmp/clamav-32gb-current-20260915` mounted at `/src`
- Source revision: Git-less content manifest
  `1fce4719f42ed92d5f0a4b8eeebb6db6268cb5981b7251894d950413cce6135f`
- Build manifest comparison: `/tmp/clamav-current-build-20260915/source-manifest.txt`
  matched a fresh source-manifest generation with `cmp` exit 0
- CMake cache SHA-256:
  `6df8b77fe9a15394b9909f85281012678c01d6b1dd72899e83710985fdfc5e05`
- `check_clamav` SHA-256:
  `b33f75bfaac218a49e500eae52ce39a8dabc30a12413825dc6dd32f77f85b732`
- `clamd` SHA-256:
  `8a62e8b65509d774bfbcf61b4251caa9fcf19c8321562981a4fd22feb7b39b54`
- Combined report SHA-256:
  `72bc0a897421e987bc78ea5190e0cf961f0934010e173844baa385a5ca846a7f`
- Report path retained in the validation container:
  `/tmp/clamav-r05-oversize-20260916/reports/oversize-fildesreport-final.json`

The rebinding used the existing offline Rust environment (`stable`, Cargo
1.97.1) and preserved `Large-file defaults: OFF` with the explicit
qualification option enabled. No software was installed or downloaded.

## Result

The current-source `check_clamav` target rebuilt successfully after CMake was
reconfigured against the regenerated inventory. The two report-producing
probes and the independent combiner each exited 0.

Both reports used an exactly `34359738369`-byte regular sparse file with
`allocated_bytes=0`; before/after metadata matched and the fixture was
removed. Both daemon health checks returned `PONG`.

With `AlertExceedsMax=no`, the report was:

- `status=24` (`CL_EMAXSIZE`), `verdict=0`, `completion=LIMIT_INCOMPLETE`
- `reason=Heuristics.Limits.Exceeded.MaxFileSize`
- `parser_operations=0`, `matcher_bytes=0`, `logical_bytes=0`,
  `temporary_bytes=0`, `files_scanned=0`, `skipped_operations=1`

With `AlertExceedsMax=yes`, the report was:

- `status=0`, `verdict=3`, `completion=DETECTION_TERMINATED`
- `last_alert=Heuristics.Limits.Exceeded.MaxFileSize`
- `parser_operations=0`, `matcher_bytes=0`, `logical_bytes=0`,
  `temporary_bytes=0`, `files_scanned=0`, `skipped_operations=3`

The daemon process, socket, pidfile, and sparse fixture were absent after
cleanup. The R05 combiner and evidence verifier passed. No capability was
promoted: full materialized 32-GiB input, production-CVD behavior, and final
release qualification remain open for R11–R15.

## Independent tracked rerun

The same R05 contract was rerun directly against the retained container using
MCP-SSH's documented tracked foreground/async execution path. The live
container identity remained
`53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9` on
`sonic1` with `x86_64`, source revision `08b3ab820e40ac8bd307290b0c78c03c94884f1b`,
and the previously recorded `clamd` SHA-256
`8a62e8b65509d774bfbcf61b4251caa9fcf19c8321562981a4fd22feb7b39b54`.
The checkout was dirty, so this is current-source development evidence, not
an immutable release qualification candidate.

The alerts-on record has SHA-256
`86d952f62e53c2db1210b695f12ac7ae01b88071614efa77865eaa13982de458`; the
alerts-off record has SHA-256
`04308b0856399808dd18f47a218d3cd0df66173620196e131da59c6d077e2a35`; and the
combined bundle has SHA-256
`35d3c9de0bb91a43c5246493189b858f67cf5632d6b5c69180607b0725a31d93`.
The independent combiner exited 0 after both records were retained and
revalidated. This rerun confirms the sparse admission behavior and the
MCP-SSH extension, but does not change the qualification disposition above.
