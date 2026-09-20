# Task receipt: R13 PCRE development smoke

Task ID / parent milestone: `R13` / `R04`

Scope: exercise the current Sonic1 build through a real PCRE database load,
full-map match, post-PCRE subject-release marker, and JSON result. This is a
bounded development smoke only. It does not claim the 40-GiB PCRE subject
phase, RSS budgets, or release qualification.

Environment and identity:

- Source commit: `e9032cb681d5881444d81cdd60e22a27c197f8b2`
- Remote source manifest SHA-256:
  `731a30796ca7e93c515aede1e47693dba179e1c60860e859ff4906c0658977ef`
- Remote `CMakeCache.txt` SHA-256:
  `913c90b1a4178b9422e9249a21e5763755abd43c457d64d6dc0bc896d8a4c844`
- Remote `clamscan` SHA-256:
  `e819ac6cf73d8fa8ad0beb50e859bd90495920a088e97c42b00affeb3ccc3264`
- The scan used the current `build-roadmap-20260920` binary and explicitly
  supplied its checked-in CVD certificate directory with `--cvdcertsdir`.

Fixtures and retained result:

- Custom signature: `PcreTail;Engine:81-255,Target:0;1;5441494c4d41524b;0/TAILMARK/`
- Signature SHA-256:
  `8ab6f408dce9737e01980281d8d7ad2bed5b202325531af6d5026f12128acda9`
- Fixture: 4096 `A` bytes followed by `TAILMARK\n`, 4105 bytes total.
- Fixture SHA-256:
  `5bfd8e56158a695474ced99ef13e088d730160fd924915b44acfad50377a4a20`
- JSON report SHA-256:
  `e5ddd0669efb415b847f7d146d8a3f662a4ef5b9931f54be157a036670e8b75d`

Observed result:

- Database load succeeded and the engine reported one generic PCRE matcher.
- The PCRE phase ran against the full 4105-byte map and located the exact
  `TAILMARK` match at offset 4096.
- Runtime markers were ordered `before-pcre` -> `pcre` ->
  `post-pcre-before-deep-parse`, with `subject_released=1` at the post-PCRE
  marker.
- The JSON result reported `DETECTION_TERMINATED`, `matcher_bytes=4105`,
  `temporary_bytes=0`, and `last_alert=PcreTail.UNOFFICIAL`.
- Exit status was 1 because the custom development signature detected the
  fixture; this is the expected positive-control result.

Verification and limits:

- This smoke verifies the current PCRE control path and release marker on a
  small subject only.
- It did not collect process-tree RSS samples, so it cannot satisfy the
  `pcre<=40 GiB` or `post-pcre<12 GiB` evidence contract.
- It did not exercise the full-size sparse fixture, deep parser residency,
  queue pressure, or fanotify permission events.

State: `development-verified`
