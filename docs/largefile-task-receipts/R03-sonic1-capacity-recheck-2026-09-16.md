# Task receipt: R03 Sonic1 capacity recheck — 2026-09-16

## Scope

This receipt records a read-only capacity recheck through the documented
MCP-SSH tracked asynchronous command path. It is runner-preflight evidence,
not build or qualification evidence.

## Identity and commands

- Host: `sonic1`, login profile: `sonic1-camera-key`;
- platform: `Linux 5.15.0-190-generic x86_64`;
- preview admitted `ssh_command_start` with a requested and effective timeout
  of 3600 seconds;
- tracked jobs `job_a26b65d181f344859c7f25765d33e4a3` (`uname`) and
  `job_a1a3d185634c46cdab9fbc166e19c97d` (`free -b`) and
  `job_696f24883d5247028aec0ceb37986f41` (`df -B1 /tmp`) each reached
  terminal success with exit 0; their bounded outputs were retrieved through
  `ssh_command_output`.

## Observed capacity

`free -b` reported 66,800,082,944 total bytes and 63,953,227,776 available
bytes. This exceeds the roadmap's 48-GiB effective-memory-headroom minimum.

`df -B1 /tmp` reported 316,464,824,320 filesystem bytes, 245,300,711,424
used, and 57,167,429,632 available bytes. This is below the roadmap's
68-GiB disk-backed temporary-space minimum and below the full qualification
profile's required temporary headroom.

A read-only `du -x -d 1 -B1 /tmp` inventory completed through tracked job
`job_e1e97a1d5df4404eacdecf43ee40bdb2` with exit 0. The largest named trees
were `clamav-materialized-edge-20260909` at 34,359,775,232 bytes and
`clamav-32gb-current-20260915` at 34,902,831,104 bytes. The latter is the
known stale source bind, so neither tree was removed or repurposed; deletion
requires an explicit cleanup decision after checking retained-evidence needs.

## Decision

Memory capacity is currently sufficient, but the runner remains blocked for
full-size qualification by temporary-space capacity. No source was staged,
no Docker container was executed, and no qualification result was promoted.

State: `runner-preflight-partial; temporary-space-blocked`.
